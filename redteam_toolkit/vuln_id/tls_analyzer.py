"""
TLS/SSL configuration analyzer — fully passive: connects and inspects the
negotiated protocol/cipher/certificate. Never sends a crafted exploit
payload (e.g. no actual Heartbleed probe — a vulnerable OpenSSL version is
flagged via the fingerprint + cve_correlation modules instead, by version
identification, not by attempting the exploit).

Certificate inspection deliberately does NOT validate the trust chain
(verify_mode=CERT_NONE) — this module's job is to report what's actually
configured, including self-signed/untrusted certs, not to reject them
before we can even look at them. Because of that, the certificate must be
parsed manually from its DER bytes (ssl.getpeercert() returns an empty
dict whenever verify_mode is CERT_NONE) rather than relying on the
stdlib ssl module's own parsed-dict representation.
"""

from __future__ import annotations

import socket
import ssl
from datetime import UTC, datetime

from cryptography import x509
from cryptography.x509.oid import NameOID

from redteam_toolkit.core.models import Finding, FindingCategory, Severity
from redteam_toolkit.core.netutil import extract_host
from redteam_toolkit.recon.base import BaseReconModule

DEPRECATED_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
WEAK_CIPHER_KEYWORDS = ("RC4", "DES", "NULL", "EXPORT", "ANON", "MD5")


def parse_certificate(cert_der: bytes) -> dict:
    """Extract the fields this module cares about from a DER-encoded
    certificate, independent of whether the chain was trusted."""
    cert = x509.load_der_x509_certificate(cert_der)

    not_after = getattr(cert, "not_valid_after_utc", None)
    if not_after is None:  # older cryptography versions lack the _utc accessor
        not_after = cert.not_valid_after.replace(tzinfo=UTC)

    san_names: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_names = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass

    common_name = None
    cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if cn_attrs:
        common_name = cn_attrs[0].value

    return {"not_after": not_after, "san_names": san_names, "common_name": common_name}


def check_hostname_match(parsed_cert: dict, host: str) -> bool:
    for san in parsed_cert.get("san_names", []):
        if san == host:
            return True
        if san.startswith("*.") and host.endswith(san[1:]) and host != san[2:]:
            return True
    return parsed_cert.get("common_name") == host


class TLSAnalyzerModule(BaseReconModule):
    name = "tls_analyzer"
    category = "vuln-id"

    def __init__(self, engagement, connect_fn=None, port: int = 443, timeout: float = 5.0):
        super().__init__(engagement)
        self.port = port
        self.timeout = timeout
        # Injectable: returns a dict {protocol, cipher, not_after, hostname_match}
        self._connect = connect_fn or self._default_connect

    def scan(self, target: str, port: int | None = None) -> list[Finding]:
        host = extract_host(target)
        self.engagement.authorize_action(self.name, host, "tls_inspect", category=self.category)

        try:
            info = self._connect(host, port or self.port)
        except Exception as exc:
            return [Finding(
                module=self.name,
                title="TLS connection failed",
                severity=Severity.INFO,
                category=FindingCategory.VULN_ID,
                target=target,
                description=str(exc),
            )]

        findings = []

        protocol = info.get("protocol")
        if protocol in DEPRECATED_PROTOCOLS:
            findings.append(Finding(
                module=self.name,
                title=f"Deprecated protocol supported: {protocol}",
                severity=Severity.HIGH,
                category=FindingCategory.VULN_ID,
                target=target,
                description=f"The server negotiated {protocol}, which has known weaknesses.",
                remediation="Disable SSLv2/SSLv3/TLSv1.0/TLSv1.1 — require TLSv1.2 or higher.",
                cvss_score=7.4,
            ))

        cipher = info.get("cipher")
        if cipher and any(weak in cipher.upper() for weak in WEAK_CIPHER_KEYWORDS):
            findings.append(Finding(
                module=self.name,
                title=f"Weak cipher negotiated: {cipher}",
                severity=Severity.HIGH,
                category=FindingCategory.VULN_ID,
                target=target,
                description=f"Cipher suite {cipher} is considered weak or broken.",
                remediation="Restrict the server's cipher suite list to modern AEAD ciphers.",
                cvss_score=7.4,
            ))

        not_after = info.get("not_after")
        if not_after and not_after < datetime.now(UTC):
            findings.append(Finding(
                module=self.name,
                title="TLS certificate expired",
                severity=Severity.HIGH,
                category=FindingCategory.VULN_ID,
                target=target,
                description=f"Certificate expired on {not_after.isoformat()}.",
                remediation="Renew the certificate immediately.",
                cvss_score=5.3,
            ))

        if info.get("hostname_match") is False:
            findings.append(Finding(
                module=self.name,
                title="Certificate hostname mismatch",
                severity=Severity.MEDIUM,
                category=FindingCategory.VULN_ID,
                target=target,
                description=f"Certificate does not cover hostname {host}.",
                cvss_score=5.3,
            ))

        if not findings:
            findings.append(Finding(
                module=self.name,
                title="TLS configuration looks healthy",
                severity=Severity.INFO,
                category=FindingCategory.VULN_ID,
                target=target,
                description=f"Negotiated {protocol} with {cipher}; certificate current and matching.",
            ))

        return findings

    def _default_connect(self, host: str, port: int) -> dict:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # we inspect the cert ourselves; not validating chain trust here
        with socket.create_connection((host, port), timeout=self.timeout) as sock, \
                context.wrap_socket(sock, server_hostname=host) as ssock:
            cert_der = ssock.getpeercert(binary_form=True)
            cipher_info = ssock.cipher()

            not_after = None
            hostname_match = None
            if cert_der:
                parsed = parse_certificate(cert_der)
                not_after = parsed["not_after"]
                hostname_match = check_hostname_match(parsed, host)

            return {
                "protocol": ssock.version(),
                "cipher": cipher_info[0] if cipher_info else None,
                "not_after": not_after,
                "hostname_match": hostname_match,
            }
