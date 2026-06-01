"""Command-line entry points.

Two commands are installed:

* ``chute``         -- the agent you run on your Mac.
* ``chuted``  -- the daemon you run on the VPS.

Everything can also be set via env vars (CHUTE_SERVER, CHUTE_TOKEN, ...) so a
systemd/launchd unit needs no arguments.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib
import logging
import os
import secrets
import sys
from pathlib import Path

from . import certs
from .auth import Authorizer
from .client import Tunnel
from .server import Server


def _env(name: str, default: str | None = None) -> str | None:
    return os.environ.get(name, default)


def _build_authorizer(token: str) -> Authorizer | None:
    """Resolve the ``CHUTE_AUTHORIZER`` import-string to an Authorizer, or return
    None so the Server falls back to the single-token default.

    Format is Gunicorn-style ``package.module:attr``. If ``attr`` is callable (a
    class or a factory) it is called with no arguments -- a database-backed
    authorizer reads its own config from the environment; an already-built instance
    is used as-is. This is the only hook for injecting an alternative authorizer.
    """
    spec = (os.environ.get("CHUTE_AUTHORIZER") or "").strip()
    if not spec:
        return None
    module_path, sep, attr = spec.partition(":")
    if not sep or not module_path or not attr:
        raise SystemExit(f"CHUTE_AUTHORIZER must be 'module:attr', got {spec!r}")
    try:
        target = getattr(importlib.import_module(module_path), attr)
    except (ImportError, AttributeError) as exc:
        raise SystemExit(f"CHUTE_AUTHORIZER {spec!r} could not be imported: {exc}") from exc
    authorizer = target() if callable(target) else target
    if not isinstance(authorizer, Authorizer):
        raise SystemExit(
            f"CHUTE_AUTHORIZER {spec!r} did not resolve to an Authorizer "
            "(needs an async authenticate method)"
        )
    return authorizer


def _env_bool(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


# -- agent (Mac) --------------------------------------------------------------
def agent_main(argv: list[str] | None = None) -> int:
    # Optional leading verb: `chute http <port>` / `chute https <port>`.
    # Bare `chute <port>` stays http for backward compatibility.
    raw = list(sys.argv[1:]) if argv is None else list(argv)
    scheme = "http"
    if raw and raw[0] in ("http", "https"):
        scheme = raw.pop(0)

    p = argparse.ArgumentParser(
        prog="chute",
        description="chute tunnel agent. Usage: chute [http|https] <port> [options]",
    )
    p.add_argument(
        "local_port",
        type=int,
        nargs="?",
        default=int(_env("CHUTE_LOCAL_PORT", "8000")),
        help="local port to expose (default 8000)",
    )
    p.add_argument(
        "--server", default=_env("CHUTE_SERVER"), help="server hostname/IP (env CHUTE_SERVER)"
    )
    p.add_argument("--token", default=_env("CHUTE_TOKEN"), help="shared secret (env CHUTE_TOKEN)")
    p.add_argument("--control-port", type=int, default=int(_env("CHUTE_CONTROL_PORT", "7000")))
    p.add_argument("--local-host", default=_env("CHUTE_LOCAL_HOST", "127.0.0.1"))
    p.add_argument(
        "--server-cert",
        default=_env("CHUTE_SERVER_CERT"),
        help="path to the pinned server certificate (PEM)",
    )
    p.add_argument(
        "--subdomain",
        default=_env("CHUTE_SUBDOMAIN"),
        help="requested public subdomain label (default: server auto-assigns)",
    )
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(raw)

    _setup_logging(args.verbose)
    if not args.server or not args.token:
        p.error("--server and --token are required (or set CHUTE_SERVER / CHUTE_TOKEN)")

    tunnel = Tunnel(
        server=args.server,
        token=args.token,
        local_port=args.local_port,
        local_host=args.local_host,
        control_port=args.control_port,
        server_cert=args.server_cert,
        scheme=scheme,
        subdomain=args.subdomain,
    )

    async def _run() -> None:
        task = asyncio.ensure_future(tunnel.serve_forever())
        url = await tunnel.wait_until_ready()
        print(f"\n  chute  {url}  ->  {args.local_host}:{args.local_port}\n")
        await task

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        return 0
    return 0


# -- server (VPS) -------------------------------------------------------------
def server_main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="chuted", description="chute tunnel server")
    sub = p.add_subparsers(dest="cmd")

    gen = sub.add_parser("gen-cert", help="generate a pinned self-signed cert")
    gen.add_argument("--host", required=True, help="public hostname or IP of this server")
    gen.add_argument("--cert", default="chute-cert.pem")
    gen.add_argument("--key", default="chute-key.pem")

    sub.add_parser("gen-token", help="print a fresh random token")

    run = sub.add_parser("run", help="run the server (default)")
    _add_run_args(run)
    _add_run_args(p)  # allow `chuted` with no subcommand to mean `run`

    args = p.parse_args(argv)

    if args.cmd == "gen-cert":
        certs.generate(args.host, Path(args.cert), Path(args.key))
        print(f"wrote {args.cert} and {args.key}  (valid 10 years)")
        print(f"copy {args.cert} to the client and pass it as --server-cert")
        return 0

    if args.cmd == "gen-token":
        print(secrets.token_urlsafe(32))
        return 0

    return _run_server(args)


def _add_run_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--token", default=_env("CHUTE_TOKEN"))
    p.add_argument("--public-host", default=_env("CHUTE_PUBLIC_HOST", "0.0.0.0"))
    p.add_argument("--public-port", type=int, default=int(_env("CHUTE_PUBLIC_PORT", "80")))
    p.add_argument("--control-host", default=_env("CHUTE_CONTROL_HOST", "0.0.0.0"))
    p.add_argument("--control-port", type=int, default=int(_env("CHUTE_CONTROL_PORT", "7000")))
    p.add_argument(
        "--public-url",
        default=_env("CHUTE_PUBLIC_URL"),
        help="URL shown to the agent (e.g. http://tunnel.example.com/)",
    )
    # Multi-tenant: route by Host under this base domain and hand each agent a
    # <label>.<base-domain> URL. Typically paired with --upstream-tls behind nginx.
    p.add_argument(
        "--base-domain",
        default=_env("CHUTE_BASE_DOMAIN"),
        help="enable multi-tenant Host routing under this domain (e.g. chute.sh)",
    )
    p.add_argument(
        "--upstream-tls",
        action="store_true",
        default=_env_bool("CHUTE_UPSTREAM_TLS"),
        help="TLS is terminated upstream (e.g. nginx); advertise https:// URLs",
    )
    p.add_argument(
        "--cert",
        default=_env("CHUTE_CERT", "chute-cert.pem"),
        help="control-channel cert (pinned self-signed)",
    )
    p.add_argument("--key", default=_env("CHUTE_KEY", "chute-key.pem"), help="control-channel key")
    # Public HTTPS (optional): a browser-trusted cert, renewed out-of-band by an
    # external ACME tool (lego/certbot). chute loads + hot-reloads these files.
    p.add_argument(
        "--tls-cert",
        default=_env("CHUTE_TLS_CERT"),
        help="public TLS cert (fullchain PEM) -- enables https tunnels",
    )
    p.add_argument("--tls-key", default=_env("CHUTE_TLS_KEY"), help="public TLS private key (PEM)")
    p.add_argument("--tls-port", type=int, default=int(_env("CHUTE_TLS_PORT", "443")))
    p.add_argument(
        "--domain",
        default=_env("CHUTE_DOMAIN"),
        help="public hostname for the https URL (e.g. app.example.com)",
    )
    p.add_argument("-v", "--verbose", action="store_true")


def _run_server(args: argparse.Namespace) -> int:
    _setup_logging(getattr(args, "verbose", False))
    if not args.token:
        print("error: --token is required (or set CHUTE_TOKEN)")
        return 2

    # Multi-tenant routing peeks the Host header; if exposed directly to
    # untrusted clients it is open to HTTP request-smuggling/desync, so it must
    # sit behind a normalizing reverse proxy. Default the bind to loopback (what
    # deploy.sh does) unless the operator explicitly chose a public host.
    public_host = args.public_host
    if args.base_domain and public_host == "0.0.0.0" and not _env("CHUTE_PUBLIC_HOST"):
        public_host = "127.0.0.1"
        logging.getLogger("chute.server").info(
            "multi-tenant: binding public port to 127.0.0.1 (put nginx in front); "
            "set --public-host / CHUTE_PUBLIC_HOST to override"
        )

    ssl_ctx = None
    cert, key = Path(args.cert), Path(args.key)
    if cert.exists() and key.exists():
        ssl_ctx = certs.server_ssl_context(cert, key)
    else:
        print(f"warning: {cert}/{key} not found -- control channel will be PLAINTEXT.")
        print("         run `chuted gen-cert --host <ip>` first.")

    tls_cert = tls_key = None
    public_https_url = None
    if args.tls_cert and args.tls_key:
        tc, tk = Path(args.tls_cert), Path(args.tls_key)
        if tc.exists() and tk.exists():
            tls_cert, tls_key = tc, tk
            host = args.domain or args.public_host
            suffix = "" if args.tls_port == 443 else f":{args.tls_port}"
            public_https_url = f"https://{host}{suffix}/"
        else:
            print(f"warning: TLS cert/key not found ({tc} / {tk}) -- https disabled.")

    server = Server(
        token=args.token,
        public_host=public_host,
        public_port=args.public_port,
        control_host=args.control_host,
        control_port=args.control_port,
        public_url=args.public_url,
        ssl_context=ssl_ctx,
        tls_cert=tls_cert,
        tls_key=tls_key,
        public_tls_port=args.tls_port,
        public_https_url=public_https_url,
        base_domain=args.base_domain,
        upstream_tls=args.upstream_tls,
        authorizer=_build_authorizer(args.token),
    )
    try:
        asyncio.run(server.serve())
    except KeyboardInterrupt:
        return 0
    return 0


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s  %(message)s",
        datefmt="%H:%M:%S",
    )


if __name__ == "__main__":
    raise SystemExit(agent_main())
