import pytest
from imap_to_misp import extract_iocs_free_text

SAMPLE_TEXT = """
Alerta de seguridad. Se detectó actividad sospechosa desde la IP 198.51.100.10.
El atacante usó el dominio evil-corp.com y la URL hxxps://evil-corp.com/payload.exe.
Se encontró un fichero con hash sha256: 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef.
Contactar con admin@security-team.local para más detalles.
"""

def test_extract_ipv4():
    iocs = extract_iocs_free_text(SAMPLE_TEXT)
    assert "198.51.100.10" in iocs["ipv4"]

def test_extract_domain():
    iocs = extract_iocs_free_text(SAMPLE_TEXT)
    assert "evil-corp.com" in iocs["domains"]

def test_extract_url_with_hxxps():
    iocs = extract_iocs_free_text(SAMPLE_TEXT)
    assert "https://evil-corp.com/payload.exe" in iocs["urls"]

def test_extract_sha256():
    iocs = extract_iocs_free_text(SAMPLE_TEXT)
    assert "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" in iocs["sha256"]

def test_extract_email():
    iocs = extract_iocs_free_text(SAMPLE_TEXT)
    assert "admin@security-team.local" in iocs["emails"]