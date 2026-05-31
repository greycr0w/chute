"""Self-signed certificate handling for the control channel.

We deliberately do *not* use Let's Encrypt / a public CA for the agent<->server
control link. We control both ends, so we mint one long-lived self-signed
certificate on the server and pin it in the client. Benefits:

* zero renewal maintenance (10-year validity -> effectively fire-and-forget),
* no certbot, no ACME, no port-80 challenge dance,
* MITM protection is *stronger* than public CA TLS because the client trusts
  exactly one certificate, not every CA on earth.

The cert is a self-signed **leaf** (``CA: FALSE``): the client pins this exact
certificate via ``load_verify_locations`` + ``check_hostname=False``, so the
server presenting it verifies, while a leaked key cannot be used to mint *new*
trusted leaves (a smaller blast radius than a pinned CA).
"""

from __future__ import annotations

import datetime as _dt
import ipaddress
import ssl
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def generate(host: str, cert_path: Path, key_path: Path, *, days: int = 3650) -> None:
    """Write a self-signed cert/key pair that is valid for ``host``.

    ``host`` may be a domain or an IP address; both are added as SANs along with
    ``localhost`` / ``127.0.0.1`` so the same cert works for local testing.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])

    sans: list[x509.GeneralName] = [x509.DNSName("localhost")]
    seen = {"localhost"}
    for candidate in (host, "127.0.0.1", "::1"):
        if candidate in seen:
            continue
        seen.add(candidate)
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(candidate)))
        except ValueError:
            sans.append(x509.DNSName(candidate))

    now = _dt.datetime.now(_dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(minutes=5))
        .not_valid_after(now + _dt.timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        # Self-signed LEAF, not a CA: pinned directly by the client, but useless
        # for minting fresh trusted certs if the key ever leaks.
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )

    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)


def server_ssl_context(cert_path: Path, key_path: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    return ctx


def client_ssl_context(cert_path: Path) -> ssl.SSLContext:
    """Trust exactly the pinned server cert; skip hostname checks (self-signed)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=str(cert_path))
    ctx.check_hostname = False  # we pin the cert itself, not its hostname
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx
