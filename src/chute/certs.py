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
import os
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
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    # Create the key file 0600 from the first byte. write_bytes()+chmod() leaves a
    # TOCTOU window where the private key sits on disk at the umask default (often
    # 0644); open with a restrictive mode and fchmod() *before* writing so the key
    # material never exists at a looser mode (O_TRUNC re-asserts 0600 on regen).
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:  # fdopen owns fd; closes it on exit
        os.fchmod(fd, 0o600)
        fh.write(key_pem)


def server_ssl_context(cert_path: Path, key_path: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    # Turn off TLS session-ticket resumption (1.2 STEK + 1.3 tickets). OpenSSL
    # otherwise mints one session-ticket key at context creation and never rotates
    # it for the whole process lifetime, so a later key leak retroactively breaks
    # forward secrecy of every resumed session. The control channel is a single
    # long-lived connection (no resumption value) and the edge-TLS path should
    # match the documented nginx posture (`ssl_session_tickets off`) -- pure upside.
    ctx.options |= ssl.OP_NO_TICKET
    ctx.num_tickets = 0  # TLS 1.3: issue zero session tickets
    return ctx


def client_ssl_context(cert_path: Path) -> ssl.SSLContext:
    """Trust exactly the pinned server cert; skip hostname checks (self-signed)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=str(cert_path))
    ctx.check_hostname = False  # we pin the cert itself, not its hostname
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx
