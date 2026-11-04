"""Run testapp over HTTP, and a small HTTPS site with a deliberately weak TLS configuration.

    python serve.py --host 0.0.0.0 --port 8080 --tls-port 8443

The HTTPS port exists only for the Weak Cryptography weaknesses ("tls-legacy-protocols",
"tls-self-signed"): it accepts TLS 1.0 and 1.1 and presents a self-signed certificate made at
start. It serves `app.tls_app`, a page with every security header, so the other modules have
nothing to report there. Never expose either port.
"""

from __future__ import annotations

import argparse
import datetime
import ipaddress
import os
import ssl
import tempfile
import threading
from pathlib import Path

import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

try:
    from app import app, tls_app
except ImportError:  # imported as testapp.serve from the repository root
    from testapp.app import app, tls_app


def self_signed_certificate(directory: Path, names: list[str]) -> tuple[Path, Path]:
    """A fresh self-signed certificate for `names` (weakness "tls-self-signed")."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "testapp")])
    alt_names: list[x509.GeneralName] = []
    for name in names:
        try:
            alt_names.append(x509.IPAddress(ipaddress.ip_address(name)))
        except ValueError:
            alt_names.append(x509.DNSName(name))
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(alt_names), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = directory / "cert.pem", directory / "key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def tls_server(host: str, port: int, directory: Path) -> uvicorn.Server:
    cert, key = self_signed_certificate(directory, ["testapp", "localhost", "127.0.0.1"])
    config = uvicorn.Config(
        tls_app,
        host=host,
        port=port,
        ssl_certfile=str(cert),
        ssl_keyfile=str(key),
        ssl_ciphers="DEFAULT:@SECLEVEL=0",
        server_header=False,
        log_level="warning",
    )
    config.load()
    # Weakness "tls-legacy-protocols": TLS 1.0 and 1.1 are accepted.
    assert config.ssl is not None  # noqa: S101
    config.ssl.minimum_version = ssl.TLSVersion.TLSv1
    return uvicorn.Server(config)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--tls-port", type=int, default=8443)
    args = parser.parse_args()
    os.environ["TESTAPP_TLS_PORT"] = str(args.tls_port)  # the root page links the HTTPS site
    with tempfile.TemporaryDirectory() as directory:
        secure = tls_server(args.host, args.tls_port, Path(directory))
        # Only the main thread's server handles signals; the HTTPS thread ends with the process.
        threading.Thread(target=secure.run, daemon=True).start()
        uvicorn.run(app, host=args.host, port=args.port, server_header=False)


if __name__ == "__main__":
    main()
