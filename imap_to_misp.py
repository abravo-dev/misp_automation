#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
imap_to_misp.py — Ingesta de alertas por correo -> MISP (adjuntos CSV + cuerpo)

Este script se conecta a una cuenta de correo IMAP para leer mensajes no leídos,
extrae Indicadores de Compromiso (IOCs) tanto del cuerpo del email como de
ficheros CSV adjuntos, y los ingesta en una instancia de MISP como eventos y
atributos.

Características clave:
- Conexión segura a IMAP con reintentos.
- Procesamiento híbrido de IOCs (cuerpo del email y adjuntos CSV).
- Clasificación de alertas basada en reglas configurables.
- Enriquecimiento de IOCs (IPs) con GeoIP y reputación de AbuseIPDB.
- Persistencia de estado en una base de datos SQLite para evitar duplicados.
- Logging estructurado en JSON y logs de auditoría en formato CSV.
- Cliente de API MISP robusto con reintentos y manejo de errores.
- Soporte para ejecución simulada (`--dry-run`).
"""
import os
import re
import ssl
import sys
import json
import time
import argparse
import logging
import sqlite3
import hashlib
import csv
import io
import ipaddress
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Any, Iterable, Optional
import imaplib
import email
from email.header import decode_header
import requests
import yaml

try:
    import geoip2.database
except ImportError:
    geoip2 = None

# ----------------- Logging JSON -----------------
class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
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

def setup_logging(log_path: str = None, audit_path: str = None, verbose: bool = False, human_readable: bool = False):
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    # Formateador para la consola
    if human_readable:
        console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    else:
        console_formatter = JsonLogFormatter()
        
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(console_formatter)
    logger.handlers = [sh]

    # Formateador para el fichero (siempre JSON)
    if log_path:
        json_formatter = JsonLogFormatter()
        fh = logging.FileHandler(log_path)
        fh.setFormatter(json_formatter)
        logger.addHandler(fh)

    if audit_path:
        audit_logger = logging.getLogger("audit")
        audit_logger.setLevel(logging.INFO)
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
            msg_id TEXT PRIMARY KEY, message_date TEXT,
            processed_at TEXT, event_ids TEXT
        )""")
        c.execute("""
        CREATE TABLE IF NOT EXISTS ip_cache (
            ip TEXT PRIMARY KEY, country TEXT,
            abuse_score INTEGER, checked_at TEXT
        )""")
        self.conn.commit()

    def already_processed(self, msg_id: str) -> bool:
        c = self.conn.cursor()
        c.execute("SELECT 1 FROM processed WHERE msg_id=?", (msg_id,))
        return c.fetchone() is not None

    def mark_processed(self, msg_id: str, message_date: str, event_ids: List[str]):
        c = self.conn.cursor()
        c.execute("INSERT OR REPLACE INTO processed VALUES (?,?,?,?)",
                  (msg_id, message_date, datetime.now(timezone.utc).isoformat(), json.dumps(event_ids)))
        self.conn.commit()

    def get_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        c = self.conn.cursor()
        c.execute("SELECT country, abuse_score, checked_at FROM ip_cache WHERE ip=?", (ip,))
        row = c.fetchone()
        return {"country": row[0], "abuse_score": row[1], "checked_at": row[2]} if row else None

    def set_ip(self, ip: str, country: str, abuse_score: Optional[int]):
        c = self.conn.cursor()
        c.execute("INSERT OR REPLACE INTO ip_cache(ip, country, abuse_score, checked_at) VALUES (?,?,?,?)",
                  (ip, country or "", int(abuse_score) if abuse_score is not None else None, datetime.now(timezone.utc).isoformat()))
        self.conn.commit()

    def close(self):
        self.conn.close()

# ----------------- IOC Regex and Helpers -----------------
RE_IPv4   = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b')
RE_DOMAIN = re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b', re.I)
RE_URL    = re.compile(r'\bhttps?://[^\s<>"\'()]+', re.I)
RE_SHA256 = re.compile(r'\b[a-fA-F0-9]{64}\b')
RE_EMAIL  = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')

def is_ip_whitelisted(ip: str, whitelist_ranges: List[str]) -> bool:
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

def extract_iocs_free_text(text: str) -> Dict[str, List[str]]:
    t = text.replace("hxxp://", "http://").replace("hxxps://", "https://")
    t = re.sub(r'<[^>]+>', ' ', t)
    return {
        "ipv4":   list(set(RE_IPv4.findall(t))),
        "domains":list(set(RE_DOMAIN.findall(t))),
        "urls":   list(set(RE_URL.findall(t))),
        "sha256": list(set(RE_SHA256.findall(t))),
        "emails": list(set(RE_EMAIL.findall(t))),
    }

# ----------------- Email Processing -----------------
class IMAPClient:
    def __init__(self, host, user, password, mailbox="INBOX", port=993, ssl_verify=True):
        self.host, self.user, self.password = host, user, password
        self.mailbox, self.port, self.ssl_verify = mailbox, port, ssl_verify
        self.M = None

    def connect(self, retries=3, base_sleep=2):
        for i in range(1, retries + 1):
            try:
                ctx = ssl.create_default_context()
                if not self.ssl_verify:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                self.M = imaplib.IMAP4_SSL(self.host, self.port, ssl_context=ctx)
                self.M.login(self.user, self.password)
                self.M.select(f'"{self.mailbox}"') # Importante: entrecomillar el mailbox
                logging.info("IMAP connection successful")
                return
            except Exception as e:
                logging.error("IMAP connect attempt %d failed: %s", i, str(e))
                time.sleep(base_sleep * i)
        raise RuntimeError("Could not connect to IMAP after several retries")

    def fetch_unseen_messages(self) -> List[email.message.Message]:
        msgs = []
        try:
            typ, data = self.M.search(None, 'UNSEEN')
            if typ != 'OK': return msgs
            for num in data[0].split():
                typ, msgdata = self.M.fetch(num, '(RFC822)')
                if typ != 'OK': continue
                raw = msgdata[0][1]
                msg = email.message_from_bytes(raw)
                msgs.append(msg)
        except Exception as e:
            logging.error("Failed to fetch unseen messages: %s", e)
        return msgs

    def logout(self):
        try:
            if self.M:
                self.M.close()
                self.M.logout()
        except Exception:
            pass

def msg_id_or_hash(msg: email.message.Message) -> str:
    mid = msg.get("Message-ID")
    if mid: return mid
    raw = msg.as_bytes()
    return hashlib.sha1(raw).hexdigest()

def parse_email_parts(msg: email.message.Message) -> Dict[str, Any]:
    subject_raw = msg.get("Subject", "")
    decoded_header = decode_header(subject_raw)
    subject = decoded_header[0][0]
    if isinstance(subject, bytes):
        subject = subject.decode(decoded_header[0][1] or 'utf-8', 'ignore')

    body_texts, csv_files = [], []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            fname = (part.get_filename() or "").lower()
            if ctype in ("text/plain", "text/html") and not part.get("Content-Disposition"):
                payload = part.get_payload(decode=True)
                if payload: body_texts.append(payload.decode(part.get_content_charset() or 'utf-8', 'ignore'))
            elif ctype in ("text/csv", "application/octet-stream") or fname.endswith(".csv"):
                payload = part.get_payload(decode=True)
                if payload: csv_files.append(payload)
    else:
        payload = msg.get_payload(decode=True)
        if payload: body_texts.append(payload.decode(msg.get_content_charset() or 'utf-8', 'ignore'))

    return {
        "subject": subject, "date": msg.get("Date", ""),
        "body_text": "\n".join(body_texts), "csv_attachments": csv_files
    }

# ----------------- CSV and Detection Logic -----------------
def iter_csv_rows(file_bytes: bytes) -> Iterable[Dict[str, str]]:
    try:
        decoded_file = file_bytes.decode("utf-8")
    except UnicodeDecodeError:
        decoded_file = file_bytes.decode("latin-1", "replace")
    
    f = io.StringIO(decoded_file)
    reader = csv.DictReader(f)
    for row in reader:
        yield { (k or "").strip(): (v or "").strip() for k, v in row.items() }

_COMPILED_PATTERNS = [
    ("brute_force", re.compile(r"(user\s+login\s+denied|failed\s+login|authentication\s+failed)", re.I)),
    ("geo_block",   re.compile(r"initiator\s+from\s+country\s+blocked.*?ip:(?P<ip>\d{1,3}(?:\.\d{1,3}){3})", re.I)),
    ("port_scan",   re.compile(r"(port\s+scan|scanning)", re.I)),
]

def classify_row_from_message(message: str) -> Tuple[str, Optional[str]]:
    for det, rx in _COMPILED_PATTERNS:
        m = rx.search(message or "")
        if m: return det, (m.group("ip") if "ip" in rx.groupindex else None)
    return "suspicious_activity", None

def get_first_from_row(row: Dict[str, str], header_aliases: Dict[str, List[str]], logical_name: str) -> str:
    for alias in header_aliases.get(logical_name, []):
        if alias in row and row[alias]: return row[alias]
    return ""

def iocs_from_row(row: Dict[str, str], header_aliases: Dict[str, List[str]], add_dst_ip: bool) -> Dict[str, List[str]]:
    iocs = { "ipv4": [], "ipv4-dst": [], "domains": [], "urls": [], "sha256": [], "emails": [] }
    src_ip = get_first_from_row(row, header_aliases, "src_ip")
    dst_ip = get_first_from_row(row, header_aliases, "dst_ip")
    message = get_first_from_row(row, header_aliases, "message")

    if src_ip and RE_IPv4.match(src_ip): iocs["ipv4"].append(src_ip)
    if add_dst_ip and dst_ip and RE_IPv4.match(dst_ip): iocs["ipv4-dst"].append(dst_ip)
    
    if message:
        iocs_text = extract_iocs_free_text(message)
        for k, vals in iocs_text.items():
            if k in iocs: iocs[k].extend(vals)

    for k in list(iocs.keys()): iocs[k] = list(sorted(set(iocs[k])))
    return iocs

def classify_detection(subject: str, body: str) -> str:
    text = f"{subject}\n{body}".lower()
    if any(s in text for s in ["brute force", "fuerza bruta", "failed login"]): return "brute_force"
    if any(s in text for s in ["port scan", "escaneo de puertos", "nmap"]): return "port_scan"
    if any(s in text for s in ["phishing", "credential", "fake login"]): return "phishing"
    if any(s in text for s in ["c2", "command and control", "beacon"]): return "c2"
    if any(s in text for s in ["malware", "trojan", "virus"]): return "malware_drop"
    if any(s in text for s in ["cve-", "exploit"]): return "vuln_exploit"
    return "suspicious_activity"

# ----------------- Enrichment Services -----------------
def geoip_country(ip: str, cfg: dict, state: StateDB) -> str:
    cached = state.get_ip(ip)
    if cached and cached.get("country"): return cached["country"]

    db_path = cfg.get("GEOIP", {}).get("DB_PATH")
    if not db_path or not geoip2 or not os.path.exists(db_path): return ""
    
    country = ""
    try:
        with geoip2.database.Reader(db_path) as reader:
            r = reader.country(ip)
            country = (r.country.iso_code or "") if r and r.country else ""
    except Exception: pass
    
    state.set_ip(ip, country, cached.get("abuse_score") if cached else None)
    return country

def abuseipdb_score(ip: str, cfg: dict, state: StateDB) -> Optional[int]:
    cached = state.get_ip(ip)
    if cached and cached.get("abuse_score") is not None:
        return int(cached["abuse_score"])

    ab_cfg = cfg.get("ABUSEIPDB", {})
    if not ab_cfg.get("ENABLED", False): return None
    api_key = os.environ.get(ab_cfg.get("API_KEY_ENV", "ABUSEIPDB_API_KEY"), "")
    if not api_key: return None

    headers = {"Key": api_key, "Accept": "application/json"}
    params  = {"ipAddress": ip, "maxAgeInDays": 90}
    score = None
    try:
        resp = requests.get(
            ab_cfg.get("API_URL", "https://api.abuseipdb.com/api/v2/check"),
            headers=headers, params=params, timeout=ab_cfg.get("TIMEOUT", 15)
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})
        score = int(data.get("abuseConfidenceScore", 0))
    except Exception as e:
        logging.error("AbuseIPDB query failed for %s: %s", ip, e)

    state.set_ip(ip, (cached.get("country") if cached else ""), score)
    time.sleep(ab_cfg.get("RATE_SLEEP", 0.8))
    return score

# ----------------- MISP API Client -----------------
class MISPClient:
    def __init__(self, url: str, api_key: str, verify_ssl: bool = True, rate_sleep: float = 0.3):
        self.url = url.rstrip("/")
        self.headers = {"Authorization": api_key, "Accept": "application/json", "Content-Type": "application/json"}
        self.verify = verify_ssl
        self.sleep = rate_sleep

    def _request(self, method, path, **kwargs):
        for i in range(1, 4):
            try:
                r = requests.request(method, f"{self.url}{path}", headers=self.headers, verify=self.verify, timeout=30, **kwargs)
                if r.status_code >= 500: raise RuntimeError(f"MISP server error: {r.status_code}")
                r.raise_for_status()
                time.sleep(self.sleep)
                return r.json()
            except Exception as e:
                logging.error("%s %s attempt %d failed: %s", method.upper(), path, i, str(e))
                time.sleep(1.5 * i)
        raise RuntimeError(f"Failed to execute MISP request {method.upper()} {path} after retries")

    def search_attribute(self, value: str, type_hint: str = None) -> bool:
        payload = {"value": value}
        if type_hint: payload["type"] = type_hint
        try:
            j = self._request("post", "/attributes/restSearch", json=payload)
            return len(j.get("response", {}).get("Attribute", [])) > 0
        except Exception as e:
            logging.error("Attribute search failed: %s", e)
            return False

    def create_event(self, info: str, date: str, threat_level_id: int, analysis: int, distribution: int) -> str:
        payload = {"Event": {"info": info, "date": date, "threat_level_id": threat_level_id, "analysis": analysis, "distribution": distribution}}
        j = self._request("post", "/events", json=payload)
        return j["Event"]["id"]

    def add_tag_to_event(self, event_id: str, tag_name: str):
        payload = {"Tag": {"name": tag_name}}
        try:
            self._request("post", f"/events/addTag/{event_id}", json=payload)
        except Exception as e:
            logging.error("Failed to tag event %s with %s: %s", event_id, tag_name, e)

    def add_attribute(self, event_id: str, category: str, attr_type: str, value: str, comment: str, to_ids: bool):
        payload = {"Attribute": {"event_id": event_id, "category": category, "type": attr_type, "value": value, "to_ids": to_ids, "comment": comment}}
        self._request("post", "/attributes", json=payload)

# ----------------- Mapping & Template Rendering -----------------
def map_detection(mappings: Dict[str, Any], detection_key: str, ioc_value: str, extra: Dict[str, Any], row_data: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    defaults = mappings.get("defaults", {})
    m = mappings.get(detection_key, {})
    
    short_desc = m.get("short_desc", detection_key.replace("_", " ").title())
    info = f"Detección: {short_desc} - {ioc_value}"
    
    attr_template = m.get("attr_template", "IOC: {ioc}")
    render_context = {**(row_data or {}), **extra, 'ioc': ioc_value}
    
    comment = attr_template
    for key, val in render_context.items():
        placeholder = "{" + key.strip() + "}"
        comment = comment.replace(placeholder, str(val))

    return {
        "event_info": info, "attr_comment": comment,
        "tags": list(set(defaults.get("base_tags", []) + m.get("tags", []))),
        "misp_type": m.get("misp_type", "comment"), "category": m.get("category", "Other"),
        "to_ids": m.get("to_ids", 0), "distribution": defaults.get("distribution", 1),
        "threat_level_id": defaults.get("event_threat_level_id", 4), "analysis": defaults.get("event_analysis", 0),
        "tlp": m.get("tlp", defaults.get("tlp", "green")),
        "workflow_state": m.get("workflow_state", "incomplete"),
        "workflow_todo": m.get("workflow_todo", "unknown"),
        "threat_actor": m.get("threat_actor", "Unknown"),
        "mitre_id": m.get("mitre_id", None)
    }

# ----------------- Main Processing Pipeline -----------------
def process_once(cfg, mappings, state: StateDB, dry_run=False):
    audit_log = logging.getLogger("audit")
    
    imap = IMAPClient(
        host=cfg["IMAP"]["HOST"], user=cfg["IMAP"]["USER"], password=os.environ.get("IMAP_PASS", ""),
        mailbox=cfg["IMAP"].get("MAILBOX", "INBOX"), port=cfg["IMAP"].get("PORT", 993),
        ssl_verify=cfg["IMAP"].get("SSL_VERIFY", True),
    )
    imap.connect()
    messages = imap.fetch_unseen_messages()
    logging.info("Unread emails found: %d", len(messages))

    if not messages:
        imap.logout()
        return

    misp = MISPClient(
        url=os.environ.get("MISP_URL", cfg["MISP"]["URL"]),
        api_key=os.environ.get("MISP_API_KEY", ""),
        verify_ssl=cfg["MISP"].get("VERIFY_SSL", True),
    )

    max_attrs = cfg["POLICY"].get("MAX_ATTRS_PER_EVENT", 120)
    header_aliases = cfg.get("CSV_HEADER_ALIASES", {})
    whitelist_ranges = cfg.get("POLICY",{}).get("WHITELIST_RANGES", [])
    add_dst_ip = cfg["POLICY"].get("ADD_DST_IP", True)
    base_date = datetime.now(timezone.utc).date().isoformat()

    for msg in messages:
        mid = msg_id_or_hash(msg)
        if state.already_processed(mid):
            logging.info("Skipping already processed message: %s", mid)
            continue

        logging.info("Processing message: %s", mid)
        parts = parse_email_parts(msg)
        
        units: List[Dict[str, Any]] = []

        for fb in parts["csv_attachments"]:
            try:
                for row in iter_csv_rows(fb):
                    message_cell = get_first_from_row(row, header_aliases, "message")
                    det, ip_hint = classify_row_from_message(message_cell or "")
                    iocs = iocs_from_row(row, header_aliases, add_dst_ip)
                    if any(iocs.values()): units.append({"src": "csv", "det": det, "ip_hint": ip_hint, "iocs": iocs, "row": row})
            except Exception as e:
                logging.error("Failed to read CSV attachment: %s", e, exc_info=True)

        iocs_body = extract_iocs_free_text(parts["body_text"])
        if any(iocs_body.values()):
            det_body = classify_detection(parts["subject"], parts["body_text"])
            units.append({"src": "body", "det": det_body, "ip_hint": None, "iocs": iocs_body, "row": None})

        if not units:
            logging.warning("No IOCs found in message %s. Marking as processed.", mid)
            if not dry_run: state.mark_processed(mid, parts["date"], [])
            continue

        buckets: Dict[str, List[Tuple[str, str, Optional[dict]]]] = {}
        for u in units:
            for ioc_type, values in u["iocs"].items():
                for value in values:
                    buckets.setdefault(u["det"], []).append((ioc_type, value, u.get("row")))

        event_ids_created = []
        for det_key, iocs_with_context in buckets.items():
            
            unique_iocs = []
            seen = set()
            for ioc_type, value, row_data in iocs_with_context:
                key = (ioc_type, value)
                if key not in seen:
                    unique_iocs.append((ioc_type, value, row_data))
                    seen.add(key)

            for i in range(0, len(unique_iocs), max_attrs):
                chunk = unique_iocs[i:i + max_attrs]
                if not chunk: continue
                first_ioc, first_row = chunk[0][1], chunk[0][2]
                
                ctx = map_detection(mappings, det_key, first_ioc, {"feed":"fw-mail"}, row_data=first_row)
                info = f"{ctx['event_info']} ({base_date})"
                
                ev_id = "dry-run-event-id"
                if not dry_run:
                    try:
                        ev_id = misp.create_event(info, base_date, ctx["threat_level_id"], ctx["analysis"], ctx["distribution"])
                        logging.info("Created MISP event %s for '%s'", ev_id, det_key)
                        audit_log.info('SUCCESS,CREATE_EVENT,%s,%s,"%s"', mid, ev_id, info)
                        event_ids_created.append(ev_id)

                        tags_to_add = set(ctx["tags"])
                        tags_to_add.add(f'tlp:{ctx["tlp"]}')
                        tags_to_add.add(f'PAP:{ctx["tlp"].upper()}')
                        tags_to_add.add(f'workflow:state="{ctx["workflow_state"]}"')
                        tags_to_add.add(f'workflow:todo="{ctx["workflow_todo"]}"')
                        if ctx.get("threat_actor") and ctx["threat_actor"] != "Unknown":
                            tags_to_add.add(f'threat-actor="{ctx["threat_actor"]}"')
                        if ctx.get("mitre_id"):
                            tags_to_add.add(f'misp-galaxy:mitre-attack-pattern="{ctx["mitre_id"]}"')
                        
                        for tag in tags_to_add:
                            misp.add_tag_to_event(ev_id, tag)

                    except Exception as e:
                        logging.error("Failed to create MISP event: %s", e, exc_info=True)
                        audit_log.error('FAILURE,CREATE_EVENT,%s,"%s","%s"', mid, info, str(e))
                        continue
                else:
                    logging.info("DRY-RUN: Would create event: %s", json.dumps({"info": info, "n_attrs": len(chunk)}))
                    audit_log.info('DRY-RUN,CREATE_EVENT,%s,"%s"', mid, info)

                for cat, val, row_data in chunk:
                    attr_ctx = map_detection(mappings, det_key, val, {"feed":"fw-mail"}, row_data=row_data)
                    final_comment = attr_ctx["attr_comment"]

                    attr_type, category, to_ids = "comment", "Other", attr_ctx["to_ids"]
                    if cat in ("ipv4", "ipv6"): attr_type, category = "ip-src", "Network activity"
                    elif cat == "ipv4-dst": attr_type, category = "ip-dst", "Network activity"
                    elif cat == "domains": attr_type, category = "domain", "Network activity"
                    elif cat == "urls": attr_type, category = "url", "Network activity"
                    elif cat == "sha256": attr_type, category = "sha256", "Payload delivery"
                    elif cat == "emails": attr_type, category = "email-src", "Payload delivery"

                    if attr_type in ("ip-src", "ip-dst") and is_ip_whitelisted(val, whitelist_ranges):
                        to_ids = False

                    if attr_type in ("ip-src", "ip-dst"):
                        country = geoip_country(val, cfg, state)
                        if country and country in cfg.get("GEOIP",{}).get("EXCLUDE_COUNTRIES",[]):
                            logging.info("Skipping IP %s from excluded country %s", val, country)
                            continue
                        score = abuseipdb_score(val, cfg, state)
                        if score is not None and score >= cfg.get("ABUSEIPDB",{}).get("MIN_SCORE_TO_FLAG",1):
                            final_comment += f" | AbuseIPDB Score: {score}"
                    
                    if not dry_run and misp.search_attribute(val, type_hint=attr_type):
                        logging.info("Attribute %s (%s) already exists. Skipping.", val, attr_type)
                        continue

                    if dry_run:
                        # Loguea el atributo simulado en modo legible si está activado
                        if cfg.get("HUMAN_LOGS"):
                            logging.info("DRY-RUN: Would add attribute -> type=%s, value=%s, to_ids=%s", attr_type, val, bool(to_ids))
                        audit_log.info('DRY-RUN,ADD_ATTRIBUTE,%s,%s,%s,%s', mid, ev_id, attr_type, val)
                    else:
                        try:
                            misp.add_attribute(ev_id, category, attr_type, val, final_comment, bool(to_ids))
                        except Exception as e:
                            audit_log.error('FAILURE,ADD_ATTRIBUTE,%s,%s,%s,%s,"%s"', mid, ev_id, attr_type, val, str(e))

        if not dry_run:
            state.mark_processed(mid, parts["date"], event_ids_created)

    imap.logout()

def main():
    ap = argparse.ArgumentParser(description="IMAP to MISP ingestor (CSV + body)")
    ap.add_argument("--config", "-c", default="config.yaml", help="Path to config YAML")
    ap.add_argument("--mappings", "-m", default="mappings.json", help="Path to mappings JSON")
    ap.add_argument("--dry-run", action="store_true", help="Simulate actions without writing to MISP")
    ap.add_argument("--once", action="store_true", help="Run a single pass and exit (for timers)")
    ap.add_argument("--verbose", "-v", action="store_true")
    ap.add_argument("--human-logs", action="store_true", help="Print human-readable logs to the console")
    args = ap.parse_args()

    try:
        cfg = load_yaml(args.config)
    except FileNotFoundError:
        # No usar logging aquí porque aún no está configurado
        print(f"CRITICAL: Config file not found at {args.config}. Exiting.", file=sys.stderr)
        sys.exit(1)
    
    # Añadir el flag al dict de config para acceso global
    cfg['HUMAN_LOGS'] = args.human_logs

    log_path = cfg.get("LOGGING", {}).get("PATH")
    audit_path = cfg.get("LOGGING", {}).get("AUDIT_PATH")
    setup_logging(log_path=log_path, audit_path=audit_path, verbose=args.verbose, human_readable=args.human_logs)

    if not os.environ.get("IMAP_PASS"): logging.warning("IMAP_PASS environment variable not set.")
    if not os.environ.get("MISP_API_KEY"): logging.warning("MISP_API_KEY environment variable not set.")

    try:
        mappings = load_json(args.mappings)
    except FileNotFoundError:
        logging.critical("Mappings file not found at %s. Exiting.", args.mappings)
        sys.exit(1)

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
