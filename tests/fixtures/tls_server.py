"""
⚠️ FOR CI USE ONLY — generates a throwaway self-signed certificate and runs
a local TLS listener for the duration of a test, never anything persistent
or network-exposed.

Used by tests/vuln_id/test_tls_analyzer.py to exercise the TLSAnalyzerModule
against a real TLS handshake instead of only synthetic injected data —
satisfying the issue's literal acceptance criteria ("generates a local
self-signed test certificate at test time").
"""

from __future__ import annotations

import datetime
import socket
import ssl
import tempfile
import threading
from pathlib import Path


def generate_self_signed_cert(
    common_name: str = "127.0.0.1", expired: bool = False
) -> tuple[bytes, bytes]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])

    now = datetime.datetime.now(datetime.UTC)
    if expired:
        not_before = now - datetime.timedelta(days=400)
        not_after = now - datetime.timedelta(days=30)
    else:
        not_before = now - datetime.timedelta(days=1)
        not_after = now + datetime.timedelta(days=365)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
    )
    cert = builder.sign(key, hashes.SHA256())

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def start_tls_server(
    common_name: str = "127.0.0.1",
    expired: bool = False,
    minimum_version: ssl.TLSVersion | None = None,
) -> tuple[socket.socket, int, threading.Event]:
    """Starts a minimal TLS listener with a freshly generated self-signed
    certificate. Returns (listening_socket, port, stop_event) — caller must
    call stop_tls_server(sock, stop_event) when done."""
    cert_pem, key_pem = generate_self_signed_cert(common_name, expired=expired)

    tmpdir = tempfile.mkdtemp()
    cert_path = Path(tmpdir) / "cert.pem"
    key_path = Path(tmpdir) / "key.pem"
    cert_path.write_bytes(cert_pem)
    key_path.write_bytes(key_pem)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert_path), str(key_path))
    if minimum_version is not None:
        context.minimum_version = minimum_version
        context.maximum_version = minimum_version

    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    raw_sock.bind(("127.0.0.1", 0))
    raw_sock.listen(5)
    port = raw_sock.getsockname()[1]

    stop_event = threading.Event()

    def serve():
        while not stop_event.is_set():
            raw_sock.settimeout(0.5)
            try:
                conn, _ = raw_sock.accept()
            except (TimeoutError, OSError):
                continue
            try:
                with context.wrap_socket(conn, server_side=True) as tls_conn:
                    try:
                        tls_conn.recv(1024)
                    except OSError:
                        pass
            except (ssl.SSLError, OSError):
                pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return raw_sock, port, stop_event


def stop_tls_server(sock: socket.socket, stop_event: threading.Event) -> None:
    stop_event.set()
    sock.close()
