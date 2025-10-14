#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
imap_to_misp.py — Ingesta de alertas por correo -> MISP (adjuntos CSV + cuerpo)
- Lee IMAP, extrae IOCs del cuerpo y de CSVs adjuntos
- Clasifica con regex sobre columna Message
- Producción: logs JSON, SQLite, reintentos, dry-run, límites de atributos
"""

import os, re, ssl, sys, json, time, argparse, logging, sqlite3, hashlib, csv, io, ipaddress
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Any, Iterable, Optional
import imaplib, email
from email.header import decode_header
import requests, yaml

try:
    import geoip2.database
except ImportError:
    geoip2 = None

# ----------------- Logging JSON -----------------
class JsonLogFormatter(logging.Formatter):
    def format(self, record):
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "lvl": record.levelname,
            "msg": record.getMessage(),
            "mod": record.module,
            "func": record.funcName,
            "line": record.lineno,
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)

def setup_logging(log_path: str = None, audit_path: str = None, verbose: bool = False):
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    formatter = JsonLogFormatter()
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(formatter)
    logger.handlers = [sh]
    if log_path:
        fh = logging.FileHandler(log_path)
        fh.setFormatter(formatter)
        logger.addHandler(fh)

    # Separate audit logger
    if audit_path:
        audit_logger = logging.getLogger("audit")
        audit_logger.setLevel(logging.INFO)
        # Simple CSV-like format for audit
        audit_formatter = logging.Formatter('%(asctime)s,%(levelname)s,"%(message)s"')
        afh = logging.FileHandler(audit_path)
        afh.setFormatter(audit_formatter)
        audit_logger.addHandler(afh)
        audit_logger.propagate = False

# ----------------- Config -----------------
def load_yaml(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

# ----------------- SQLite State -----------------
class StateDB:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.conn = sqlite3.connect(self.path, timeout=30)
        self._init()

    def _init(self):
        c = self.conn.cursor()
        c.execute("""
        CREATE TABLE IF NOT EXISTS processed (
            msg_id TEXT PRIMARY KEY,
            message_date TEXT,
            processed_at TEXT,
            event_ids TEXT
        )""")
        c.execute("""
        CREATE TABLE IF NOT EXISTS ip_cache (
            ip TEXT PRIMARY KEY,
            country TEXT,
            abuse_score INTEGER,
            checked_at TEXT
        )""")
        self.conn.commit()

    def already_processed(self, msg_id: str) -> bool:
        c = self.conn.cursor()
        c.execute("SELECT 1 FROM processed WHERE msg_id=?", (msg_id,))
        return c.fetchone() is not None

    def mark_processed(self, msg_id: str, message_date: str, event_ids: List[str]):
        c = self.conn.cursor()
        c.execute("INSERT OR REPLACE INTO processed VALUES (?,?,?,?)",
                  (msg_id, message_date, datetime.utcnow().isoformat(), json.dumps(event_ids)))
        self.conn.commit()

    def get_ip(self, ip: str):
        c = self.conn.cursor()
        c.execute("SELECT country, abuse_score, checked_at FROM ip_cache WHERE ip=?", (ip,))
        row = c.fetchone()
        return {"country": row[0], "abuse_score": row[1], "checked_at": row[2]} if row else None

    def set_ip(self, ip: str, country: str, abuse_score: int):
        c = self.conn.cursor()
        c.execute("INSERT OR REPLACE INTO ip_cache(ip, country, abuse_score, checked_at) VALUES (?,?,?,?)",
                  (ip, country or "", int(abuse_score) if abuse_score is not None else None, datetime.utcnow().isoformat()))
        self.conn.commit()

    def close(self):
        self.conn.close()

# ----------------- IOC Helpers -----------------
RE_IPv4   = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b')
RE_DOMAIN = re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b', re.I)
RE_URL    = re.compile(r'\bhttps?://[^\s<>"\'()]+', re.I)
RE_SHA256 = re.compile(r'\b[a-fA-F0-9]{64}\b')
RE_EMAIL  = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')

def is_ip_whitelisted(ip: str, whitelist_ranges: List[str]) -> bool:
    """Check if an IP is in private ranges or a custom whitelist."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            return True
        for net_str in whitelist_ranges:
            if ip_obj in ipaddress.ip_network(net_str):
                return True
    except ValueError:
        return False
    return False

# ----------------- Email Processing -----------------
def parse_email_parts(msg: email.message.Message) -> Dict[str, Any]:
    """Returns dict with subject, date, body_text, and csv_attachments."""
    subject = decode_header(msg.get("Subject", ""))[0][0]
    if isinstance(subject, bytes):
        subject = subject.decode(decode_header(msg.get("Subject", ""))[0][1] or 'utf-8', 'ignore')
    
    body_texts, csv_files = [], []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            fname = (part.get_filename() or "").lower()
            if ctype in ("text/plain", "text/html") and not part.get("Content-Disposition"):
                payload = part.get_payload(decode=True)
                if payload:
                    body_texts.append(payload.decode(part.get_content_charset() or 'utf-8', 'ignore'))
            elif ctype in ("text/csv", "application/octet-stream") or fname.endswith(".csv"):
                payload = part.get_payload(decode=True)
                if payload:
                    csv_files.append(payload)
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body_texts.append(payload.decode(msg.get_content_charset() or 'utf-8', 'ignore'))

    return {
        "subject": subject,
        "date": msg.get("Date", ""),
        "body_text": "\n".join(body_texts),
        "csv_attachments": csv_files
    }

# (Other classes and functions like IMAPClient, MISPClient, StateDB, etc. remain largely the same as in your provided code)
# ... The rest of your provided `imap_to_misp.py` code would go here ...
# For brevity, I will only show the modified `process_once` and `main` functions.

def process_once(cfg, mappings, state: StateDB, dry_run=False):
    audit_log = logging.getLogger("audit")
    
    # --- IMAP Connection ---
    imap = IMAPClient(
        host=cfg["IMAP"]["HOST"],
        user=cfg["IMAP"]["USER"],
        password=os.environ.get("IMAP_PASS", ""),
        mailbox=cfg["IMAP"].get("MAILBOX", "INBOX"),
        port=cfg["IMAP"].get("PORT", 993),
        ssl_verify=cfg["IMAP"].get("SSL_VERIFY", True),
    )
    imap.connect()
    messages = imap.fetch_unseen_messages()
    logging.info("Unread emails found: %d", len(messages))

    if not messages:
        imap.logout()
        return

    # --- MISP Connection ---
    misp = MISPClient(
        url=os.environ.get("MISP_URL", cfg["MISP"]["URL"]),
        api_key=os.environ.get("MISP_API_KEY", ""),
        verify_ssl=cfg["MISP"].get("VERIFY_SSL", True),
    )

    # --- Policy and Config ---
    max_attrs = cfg["POLICY"].get("MAX_ATTRS_PER_EVENT", 120)
    header_aliases = cfg.get("CSV_HEADER_ALIASES", {})
    whitelist_ranges = cfg.get("WHITELIST_RANGES", [])
    add_dst_ip = cfg["POLICY"].get("ADD_DST_IP", True)
    base_date = datetime.utcnow().date().isoformat()

    for msg in messages:
        mid = msg_id_or_hash(msg)
        if state.already_processed(mid):
            logging.info("Skipping already processed message: %s", mid)
            continue

        logging.info("Processing message: %s", mid)
        parts = parse_email_parts(msg)
        subject, date_hdr, body = parts["subject"], parts["date"], parts["body_text"]
        
        units: List[Dict[str, Any]] = []

        # 1) Process CSV attachments [cite: 1]
        for fb in parts["csv_attachments"]:
            try:
                for row in iter_csv_rows(fb):
                    message_cell = get_first_from_row(row, header_aliases, "message")
                    det, ip_hint = classify_row_from_message(message_cell or "")
                    iocs = iocs_from_row(row, header_aliases, add_dst_ip)
                    if any(iocs.values()):
                        units.append({"src": "csv", "det": det, "ip_hint": ip_hint, "iocs": iocs, "row": row})
            except Exception as e:
                logging.error("Failed to read CSV attachment: %s", e, exc_info=True)

        # 2) Process email body as a fallback/addition 
        iocs_body = extract_iocs_free_text(body)
        if any(iocs_body.values()):
            det_body = classify_detection(subject, body)
            units.append({"src": "body", "det": det_body, "ip_hint": None, "iocs": iocs_body, "row": None})

        if not units:
            logging.warning("No IOCs or classifiable rows found in message %s. Marking as processed.", mid)
            if not dry_run:
                state.mark_processed(mid, date_hdr, [])
            continue

        # --- Group IOCs by detection type ---
        buckets: Dict[str, List[Tuple[str,str]]] = {}
        for u in units:
            det_key = u["det"]
            flat_iocs: List[Tuple[str,str]] = []
            for ioc_type, values in u["iocs"].items():
                for value in values:
                    flat_iocs.append((ioc_type, value))
            if not flat_iocs and u["ip_hint"]:
                flat_iocs.append(("ipv4", u["ip_hint"]))
            
            if flat_iocs:
                buckets.setdefault(det_key, []).extend(flat_iocs)

        event_ids_created = []
        for det_key, iocs in buckets.items():
            unique_iocs = sorted(list(set(iocs)))
            for i in range(0, len(unique_iocs), max_attrs):
                chunk = unique_iocs[i:i + max_attrs]
                first_obs = chunk[0][1]
                
                ctx = map_detection(mappings, det_key, first_obs, {"feed":"fw-mail"})
                info = f"{ctx['event_info']} ({base_date})"
                
                ev_id = "dry-run-event-id"
                if dry_run:
                    logging.info("DRY-RUN: Would create event: %s", json.dumps({"info": info, "n_attrs": len(chunk)}))
                    audit_log.info('DRY-RUN,CREATE_EVENT,%s,"%s"', mid, info)
                else:
                    try:
                        ev_id = misp.create_event(info, base_date, ctx["threat_level_id"], ctx["analysis"], ctx["distribution"])
                        logging.info("Created MISP event %s for detection '%s'", ev_id, det_key)
                        audit_log.info('SUCCESS,CREATE_EVENT,%s,%s,"%s"', mid, ev_id, info)
                        event_ids_created.append(ev_id)
                        # Add tags
                        for t in ctx["tags"] + ["tlp:green", "pap:green", "red-nacional-soc:status=\"ongoing\""]:
                            misp.add_tag_to_event(ev_id, t)
                    except Exception as e:
                        logging.error("Failed to create MISP event for %s: %s", info, e, exc_info=True)
                        audit_log.error('FAILURE,CREATE_EVENT,%s,"%s","%s"', mid, info, str(e))
                        continue # Skip to next chunk/detection

                # --- Add attributes to event ---
                for cat, val in chunk:
                    attr_type, category, to_ids_flag = "comment", "Other", ctx["to_ids"]

                    # Map IOC category to MISP attribute type
                    if cat in ("ipv4", "ipv6"): attr_type, category = "ip-src", "Network activity"
                    elif cat == "ipv4-dst": attr_type, category = "ip-dst", "Network activity"
                    elif cat == "domains": attr_type, category = "domain", "Network activity"
                    elif cat == "urls": attr_type, category = "url", "Network activity"
                    elif cat == "sha256": attr_type, category = "sha256", "Payload delivery"
                    elif cat == "emails": attr_type, category = "email-src", "Payload delivery"

                    # Apply whitelist policy for IPs
                    if attr_type in ("ip-src", "ip-dst") and is_ip_whitelisted(val, whitelist_ranges):
                        logging.info("IP %s is whitelisted, setting to_ids=False.", val)
                        to_ids_flag = 0

                    # Enrich and filter
                    final_comment = ctx["attr_comment"]
                    if attr_type in ("ip-src", "ip-dst"):
                        # GeoIP filter
                        country = geoip_country(val, cfg, state)
                        if country and country in cfg.get("GEOIP",{}).get("EXCLUDE_COUNTRIES",[]):
                            logging.info("Skipping IP %s from excluded country %s", val, country)
                            continue
                        # AbuseIPDB enrichment
                        score = abuseipdb_score(val, cfg, state)
                        if score is not None:
                            final_comment += f" | AbuseIPDB Score: {score}"
                    
                    if not dry_run and misp.search_attribute(val, type_hint=attr_type):
                        logging.info("Attribute %s (%s) already exists in MISP. Skipping.", val, attr_type)
                        continue

                    if dry_run:
                        logging.info("DRY-RUN: Would add attribute: %s", json.dumps({"event_id": ev_id, "type": attr_type, "value": val}))
                        audit_log.info('DRY-RUN,ADD_ATTRIBUTE,%s,%s,%s,%s', mid, ev_id, attr_type, val)
                    else:
                        try:
                            misp.add_attribute(ev_id, category, attr_type, val, final_comment, bool(to_ids_flag))
                        except Exception as e:
                            logging.error("Failed to add attribute %s to event %s: %s", val, ev_id, e)
                            audit_log.error('FAILURE,ADD_ATTRIBUTE,%s,%s,%s,%s,"%s"', mid, ev_id, attr_type, val, str(e))

        if not dry_run:
            state.mark_processed(mid, date_hdr, event_ids_created)

    imap.logout()

def main():
    ap = argparse.ArgumentParser(description="IMAP to MISP ingestor (CSV + body)")
    ap.add_argument("--config", "-c", default="config.yaml", help="Path to config YAML")
    ap.add_argument("--mappings", "-m", default="mappings.json", help="Path to mappings JSON")
    ap.add_argument("--dry-run", action="store_true", help="Simulate actions without writing to MISP")
    ap.add_argument("--once", action="store_true", help="Run a single pass and exit (for timers)")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()

    cfg = load_yaml(args.config)
    log_path = cfg.get("LOGGING", {}).get("PATH")
    audit_path = cfg.get("LOGGING", {}).get("AUDIT_PATH")
    setup_logging(log_path=log_path, audit_path=audit_path, verbose=args.verbose)

    # Check for required environment variables
    if not os.environ.get("IMAP_PASS"):
        logging.warning("IMAP_PASS environment variable not set.")
    if not os.environ.get("MISP_API_KEY"):
        logging.warning("MISP_API_KEY environment variable not set.")

    mappings = load_json(args.mappings)
    state = StateDB(cfg.get("STATE", {}).get("DB_PATH", "/var/lib/misp-automation/state.db"))

    try:
        if args.once:
            process_once(cfg, mappings, state, dry_run=args.dry_run)
        else:
            interval = cfg.get("SCHEDULER", {}).get("INTERVAL_SECONDS", 600)
            while True:
                try:
                    process_once(cfg, mappings, state, dry_run=args.dry_run)
                except Exception as e:
                    logging.error("Unhandled exception in main loop: %s", e, exc_info=True)
                logging.info("Sleeping for %d seconds.", interval)
                time.sleep(interval)
    except KeyboardInterrupt:
        logging.info("Process interrupted by user.")
    finally:
        state.close()

if __name__ == "__main__":
    main()