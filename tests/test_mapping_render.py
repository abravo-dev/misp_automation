import pytest
from imap_to_misp import map_detection

MAPPINGS = {
  "defaults": { "tlp": "amber" },
  "vuln_exploit": {
    "short_desc": "Explotación de vulnerabilidad",
    "attr_template": "IOC extraído de alerta '{Message}'. IP Origen: {Src. IP}, Puerto Dst: {Dst. Port}",
    "mitre_id": "T1190"
  }
}

ROW_DATA = {
    "Message": "SSH Exploit Attempt",
    "Src. IP": "1.2.3.4",
    "Dst. Port": "22"
}

def test_event_info_render():
    ctx = map_detection(MAPPINGS, "vuln_exploit", "1.2.3.4", {}, ROW_DATA)
    assert ctx["event_info"] == "Detección: Explotación de vulnerabilidad - 1.2.3.4"

def test_attribute_comment_render():
    ctx = map_detection(MAPPINGS, "vuln_exploit", "1.2.3.4", {}, ROW_DATA)
    expected_comment = "IOC extraído de alerta 'SSH Exploit Attempt'. IP Origen: 1.2.3.4, Puerto Dst: 22"
    assert ctx["attr_comment"] == expected_comment

def test_new_fields_are_present():
    ctx = map_detection(MAPPINGS, "vuln_exploit", "1.2.3.4", {}, ROW_DATA)
    assert ctx["mitre_id"] == "T1190"
    assert ctx["tlp"] == "amber" # Heredado de defaults