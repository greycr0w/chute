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
import contextlib
import importlib
import logging
import os
import secrets
import signal
import sys
from pathlib import Path
from typing import overload

from . import certs
from .auth import Authorizer
from .client import Tunnel, _FatalError
from .server import Server

log = logging.getLogger("chute")


@overload
def _env(name: str, default: str) -> str: ...
@overload
def _env(name: str, default: None = None) -> str | None: ...
def _env(name: str, default: str | None = None) -> str | None:
    # Overloaded so callers that pass a string default get a non-optional str
    # back (used directly in int(...) / as required values), while callers with
    # no default get str | None and must handle the missing case.
    return os.environ.get(name, default)


def _int_env(name: str, default: int) -> int:
    """Integer env knob with a clean failure. ``int(_env(name, "x"))`` raises a raw
    ValueError at parser-build time (before argparse can report anything) on an
    empty or non-numeric value; this turns that into a one-line SystemExit."""
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError:
        raise SystemExit(f"{name} must be an integer, got {raw!r}") from None


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
    # Bare `chute <port>` defaults to https; pass `http` for a plaintext endpoint
    # (bare IP, no public cert, or the transparent-iframe workflow).
    raw = list(sys.argv[1:]) if argv is None else list(argv)
    scheme = "https"
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
        default=_int_env("CHUTE_LOCAL_PORT", 8000),
        help="local port to expose (default 8000)",
    )
    p.add_argument(
        "--server", default=_env("CHUTE_SERVER"), help="server hostname/IP (env CHUTE_SERVER)"
    )
    p.add_argument("--token", default=_env("CHUTE_TOKEN"), help="shared secret (env CHUTE_TOKEN)")
    p.add_argument("--control-port", type=int, default=_int_env("CHUTE_CONTROL_PORT", 7000))
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

    try:
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
    except ValueError as exc:
        p.error(str(exc))

    async def _run() -> None:
        # Ctrl-C / SIGTERM -> graceful stop (drain in-flight requests, no reconnect)
        # rather than a hard cancel. Falls back to the KeyboardInterrupt path below
        # where add_signal_handler is unsupported (non-Unix / non-main-thread loop).
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            with contextlib.suppress(NotImplementedError, RuntimeError, ValueError):
                loop.add_signal_handler(sig, tunnel.request_stop)
        serve = asyncio.ensure_future(tunnel.serve_forever())
        ready = asyncio.ensure_future(tunnel.wait_until_ready())
        # Race "connected" against "serve task finished". A fatal rejection (wrong
        # token, taken/over-limit subdomain) makes serve_forever raise _FatalError
        # before _connected is ever set -- awaiting wait_until_ready alone would then
        # hang forever AND never retrieve the task's exception. Whichever resolves
        # first wins; if it's the serve task, re-await it to surface the reason.
        await asyncio.wait({serve, ready}, return_when=asyncio.FIRST_COMPLETED)
        if not ready.done():
            ready.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await ready
            await serve  # re-raises _FatalError (or returns on a clean stop)
            return
        print(f"\n  chute  {ready.result()}  ->  {args.local_host}:{args.local_port}\n")
        await serve

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        return 0
    except _FatalError as exc:
        log.error("could not start tunnel: %s", exc)
        return 1
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
    p.add_argument("--public-port", type=int, default=_int_env("CHUTE_PUBLIC_PORT", 80))
    p.add_argument("--control-host", default=_env("CHUTE_CONTROL_HOST", "0.0.0.0"))
    p.add_argument("--control-port", type=int, default=_int_env("CHUTE_CONTROL_PORT", 7000))
    p.add_argument(
        "--public-url",
        default=_env("CHUTE_PUBLIC_URL"),
        help="URL shown to the agent (e.g. http://tunnel.example.com/)",
    )
    # Host-routed labels: route by Host under this base domain and hand each agent
    # a <label>.<base-domain> URL. Typically paired with --upstream-tls behind nginx.
    p.add_argument(
        "--base-domain",
        default=_env("CHUTE_BASE_DOMAIN"),
        help="enable Host-routed labels under this domain (e.g. chute.sh)",
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
    p.add_argument("--tls-port", type=int, default=_int_env("CHUTE_TLS_PORT", 443))
    p.add_argument(
        "--domain",
        default=_env("CHUTE_DOMAIN"),
        help="public hostname for the https URL (e.g. app.example.com)",
    )
    p.add_argument("-v", "--verbose", action="store_true")


def _run_server(args: argparse.Namespace) -> int:
    _setup_logging(getattr(args, "verbose", False))
    if not args.token:
        log.error("--token is required (or set CHUTE_TOKEN)")
        return 2

    # Host routing is loopback-only: it routes per connection, so it needs a proxy
    # that hands it one request per connection (see README "Security model").
    # Default the bind to loopback (what deploy.sh does); an explicit routable host
    # is refused by Server() below rather than silently exposed.
    public_host = args.public_host
    if args.base_domain and public_host == "0.0.0.0" and not _env("CHUTE_PUBLIC_HOST"):
        public_host = "127.0.0.1"
        logging.getLogger("chute.server").info(
            "Host routing: binding public port to 127.0.0.1 (put a reverse proxy in front)"
        )

    cert, key = Path(args.cert), Path(args.key)
    if not (cert.exists() and key.exists()):
        log.error("%s/%s not found; run `chuted gen-cert --host <host>` first", cert, key)
        return 2
    ssl_ctx = certs.server_ssl_context(cert, key)

    tls_cert = tls_key = None
    public_https_url = None
    if args.tls_cert and args.tls_key:
        tc, tk = Path(args.tls_cert), Path(args.tls_key)
        if tc.exists() and tk.exists():
            tls_cert, tls_key = tc, tk
            host = args.domain
            if not host and args.public_url:
                host = args.public_url.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
            if not host or host == "0.0.0.0":
                log.error("--domain is required when enabling public TLS")
                return 2
            suffix = "" if args.tls_port == 443 else f":{args.tls_port}"
            public_https_url = f"https://{host}{suffix}/"
        else:
            log.warning("TLS cert/key not found (%s / %s) -- https disabled", tc, tk)
    elif args.upstream_tls and not args.base_domain:
        host = args.domain
        if not host and args.public_url:
            host = args.public_url.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
        if not host or host == "0.0.0.0":
            log.error("--domain or --public-url is required for default-route --upstream-tls")
            return 2
        public_https_url = f"https://{host}/"

    try:
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
    except ValueError as exc:  # e.g. Host routing given a routable public host
        log.error("%s", exc)
        return 2
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
