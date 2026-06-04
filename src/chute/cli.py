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
import math
import os
import secrets
import signal
import ssl
import sys
from pathlib import Path
from typing import cast, overload

from . import certs
from ._files import read_private_text_file, write_new_private_text_file
from .auth import Authorizer
from .client import Tunnel, _FatalError
from .control import (
    ControlPlane,
    StaticPolicyControlPlane,
    token_sha256,
    validate_static_policy_file,
)
from .events import (
    DEFAULT_JSONL_EVENT_LOG_BACKUPS,
    DEFAULT_JSONL_EVENT_LOG_MAX_BYTES,
    EventSink,
    JsonlEventSink,
)
from .mux import _FLOW_WINDOW, validate_flow_window
from .server import (
    _DEFAULT_AUTH_TIMEOUT,
    _DEFAULT_HELLO_TIMEOUT,
    _DEFAULT_MAX_AGENTS,
    _DEFAULT_MAX_CONTROL_CONNS,
    _DEFAULT_MAX_VISITORS,
    _DEFAULT_MAX_VISITORS_PER_IP,
    _DEFAULT_RELAY_IDLE_TIMEOUT,
    Server,
)

log = logging.getLogger("chute")
_EVENT_LOG_DEFAULT = object()


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


def _read_secret_file(raw_path: str | Path, name: str) -> str:
    secret = read_private_text_file(raw_path, name).strip()
    if not secret:
        raise ValueError(f"{name} {Path(raw_path).expanduser()} is empty")
    return secret


def _parse_nonnegative_int(raw: str, name: str) -> int:
    try:
        parsed = int(raw)
    except ValueError:
        raise ValueError(f"{name} must be a non-negative integer, got {raw!r}") from None
    if parsed < 0:
        raise ValueError(f"{name} must be a non-negative integer, got {raw!r}")
    return parsed


def _nonnegative_int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return _parse_nonnegative_int(raw, name)
    except ValueError as exc:
        raise SystemExit(str(exc)) from None


def _nonnegative_int_arg(raw: str) -> int:
    try:
        return _parse_nonnegative_int(raw, "value")
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def _parse_optional_nonnegative_int(raw: str, name: str) -> int | None:
    value = raw.strip().lower()
    if value in ("", "none", "default"):
        return None
    return _parse_nonnegative_int(raw, name)


def _optional_nonnegative_int_env(name: str) -> int | None:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return None
    try:
        return _parse_optional_nonnegative_int(raw, name)
    except ValueError as exc:
        raise SystemExit(str(exc)) from None


def _optional_nonnegative_int_arg(raw: str) -> int | None:
    try:
        return _parse_optional_nonnegative_int(raw, "value")
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def _parse_positive_float(raw: str, name: str) -> float:
    try:
        parsed = float(raw)
    except ValueError:
        raise ValueError(f"{name} must be a positive finite number, got {raw!r}") from None
    if not math.isfinite(parsed) or parsed <= 0:
        raise ValueError(f"{name} must be a positive finite number, got {raw!r}")
    return parsed


def _positive_float_env(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return _parse_positive_float(raw, name)
    except ValueError as exc:
        raise SystemExit(str(exc)) from None


def _positive_float_arg(raw: str) -> float:
    try:
        return _parse_positive_float(raw, "value")
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def _parse_optional_positive_float(raw: str, name: str) -> float | None:
    value = raw.strip().lower()
    if value in ("0", "none", "off", "false", "unlimited"):
        return None
    return _parse_positive_float(raw, name)


def _optional_positive_float_env(name: str, default: float | None = None) -> float | None:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return _parse_optional_positive_float(raw, name)
    except ValueError as exc:
        raise SystemExit(str(exc)) from None


def _optional_positive_float_arg(raw: str) -> float | None:
    try:
        return _parse_optional_positive_float(raw, "value")
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def _parse_optional_positive_int(raw: str, name: str) -> int | None:
    value = raw.strip().lower()
    if value in ("0", "none", "off", "false", "unlimited"):
        return None
    try:
        parsed = int(value)
    except ValueError:
        raise ValueError(f"{name} must be a positive integer or off, got {raw!r}") from None
    if parsed < 1:
        raise ValueError(f"{name} must be a positive integer or off, got {raw!r}")
    return parsed


def _optional_positive_int_env(name: str, default: int | None) -> int | None:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return _parse_optional_positive_int(raw, name)
    except ValueError as exc:
        raise SystemExit(str(exc)) from None


def _optional_positive_int_arg(raw: str) -> int | None:
    try:
        return _parse_optional_positive_int(raw, "--max-visitors-per-ip")
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def _optional_metrics_port_arg(raw: str) -> int | None:
    try:
        return _parse_optional_positive_int(raw, "--metrics-port")
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def _optional_event_log_max_bytes_arg(raw: str) -> int | None:
    try:
        return _parse_optional_positive_int(raw, "--event-log-max-bytes")
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def _parse_flow_window(raw: str, name: str) -> int:
    try:
        parsed = int(raw)
    except ValueError:
        raise ValueError(f"{name} must be an integer byte count, got {raw!r}") from None
    return validate_flow_window(parsed, name=name)


def _flow_window_env(name: str, default: int = _FLOW_WINDOW) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return _parse_flow_window(raw, name)
    except ValueError as exc:
        raise SystemExit(str(exc)) from None


def _flow_window_arg(raw: str) -> int:
    try:
        return _parse_flow_window(raw, "--mux-flow-window")
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


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


def _build_control_plane(policy_file: str | None = None) -> ControlPlane | None:
    """Resolve built-in or imported ControlPlane config, or None for default."""
    raw_policy_file = (policy_file or os.environ.get("CHUTE_POLICY_FILE") or "").strip()
    spec = (os.environ.get("CHUTE_CONTROL_PLANE") or "").strip()
    if raw_policy_file and spec:
        raise SystemExit("set only one of CHUTE_POLICY_FILE/--policy-file or CHUTE_CONTROL_PLANE")
    if raw_policy_file:
        return StaticPolicyControlPlane(raw_policy_file)
    if not spec:
        return None
    module_path, sep, attr = spec.partition(":")
    if not sep or not module_path or not attr:
        raise SystemExit(f"CHUTE_CONTROL_PLANE must be 'module:attr', got {spec!r}")
    try:
        target = getattr(importlib.import_module(module_path), attr)
    except (ImportError, AttributeError) as exc:
        raise SystemExit(f"CHUTE_CONTROL_PLANE {spec!r} could not be imported: {exc}") from exc
    control_plane = target() if callable(target) else target
    if not isinstance(control_plane, ControlPlane):
        raise SystemExit(
            f"CHUTE_CONTROL_PLANE {spec!r} did not resolve to a ControlPlane "
            "(needs async admit_tunnel, renew_lease, and poll_policy_updates methods)"
        )
    return control_plane


def _build_event_sink(
    event_log_file: str | None = None,
    *,
    event_log_max_bytes: object = _EVENT_LOG_DEFAULT,
    event_log_backups: object = _EVENT_LOG_DEFAULT,
) -> EventSink | None:
    """Resolve built-in or imported EventSink config, or None for the no-op default."""
    raw_event_log_file = (event_log_file or os.environ.get("CHUTE_EVENT_LOG_FILE") or "").strip()
    spec = (os.environ.get("CHUTE_EVENT_SINK") or "").strip()
    if raw_event_log_file and spec:
        raise SystemExit(
            "set only one of CHUTE_EVENT_LOG_FILE/--event-log-file or CHUTE_EVENT_SINK"
        )
    if not raw_event_log_file and spec:
        module_path, sep, attr = spec.partition(":")
        if not sep or not module_path or not attr:
            raise SystemExit(f"CHUTE_EVENT_SINK must be 'module:attr', got {spec!r}")
        try:
            target = getattr(importlib.import_module(module_path), attr)
        except (ImportError, AttributeError) as exc:
            raise SystemExit(f"CHUTE_EVENT_SINK {spec!r} could not be imported: {exc}") from exc
        event_sink = target() if callable(target) else target
        if not isinstance(event_sink, EventSink):
            raise SystemExit(
                f"CHUTE_EVENT_SINK {spec!r} did not resolve to an EventSink "
                "(needs async lifecycle/stat methods)"
            )
        return event_sink
    if event_log_max_bytes is _EVENT_LOG_DEFAULT:
        resolved_max_bytes = _optional_positive_int_env(
            "CHUTE_EVENT_LOG_MAX_BYTES", DEFAULT_JSONL_EVENT_LOG_MAX_BYTES
        )
    else:
        resolved_max_bytes = cast(int | None, event_log_max_bytes)
    if event_log_backups is _EVENT_LOG_DEFAULT:
        resolved_backups = _nonnegative_int_env(
            "CHUTE_EVENT_LOG_BACKUPS", DEFAULT_JSONL_EVENT_LOG_BACKUPS
        )
    else:
        resolved_backups = cast(int, event_log_backups)
    if raw_event_log_file:
        return JsonlEventSink(
            raw_event_log_file,
            max_bytes=resolved_max_bytes,
            backup_count=resolved_backups,
        )
    return None


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
    p.add_argument(
        "--token-file",
        default=_env("CHUTE_TOKEN_FILE"),
        help="read the shared secret from a 0600 file (env CHUTE_TOKEN_FILE)",
    )
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
    p.add_argument(
        "--mux-flow-window",
        type=_flow_window_arg,
        default=_flow_window_env("CHUTE_MUX_FLOW_WINDOW"),
        help="preferred mux flow-control window in bytes (env CHUTE_MUX_FLOW_WINDOW)",
    )
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(raw)

    _setup_logging(args.verbose)
    token = args.token
    if token and args.token_file:
        p.error("set only one of --token/CHUTE_TOKEN or --token-file/CHUTE_TOKEN_FILE")
    if not token and args.token_file:
        try:
            token = _read_secret_file(args.token_file, "--token-file")
        except ValueError as exc:
            p.error(str(exc))
    if not args.server or not token:
        p.error(
            "--server and --token are required "
            "(or set CHUTE_SERVER plus CHUTE_TOKEN / CHUTE_TOKEN_FILE)"
        )

    try:
        tunnel = Tunnel(
            server=args.server,
            token=token,
            local_port=args.local_port,
            local_host=args.local_host,
            control_port=args.control_port,
            server_cert=args.server_cert,
            scheme=scheme,
            subdomain=args.subdomain,
            mux_flow_window=args.mux_flow_window,
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
        try:
            public_url = ready.result()
        except Exception:
            # wait_until_ready() and serve_forever() can surface the same fatal
            # handshake error. Retrieve the serve task's exception too so the CLI
            # exits cleanly instead of leaving "Task exception was never retrieved".
            if serve.done():
                with contextlib.suppress(Exception):
                    await serve
            else:
                serve.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await serve
            raise
        print(f"\n  chute  {public_url}  ->  {args.local_host}:{args.local_port}\n")
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
    raw = list(sys.argv[1:]) if argv is None else list(argv)
    commands = {
        "gen-cert",
        "gen-token",
        "hash-token",
        "validate-policy",
        "run",
        "-h",
        "--help",
    }
    if not raw or raw[0] not in commands:
        raw.insert(0, "run")  # allow `chuted --token ...` with no explicit subcommand

    p = argparse.ArgumentParser(prog="chuted", description="chute tunnel server")
    sub = p.add_subparsers(dest="cmd")

    gen = sub.add_parser("gen-cert", help="generate a pinned self-signed cert")
    gen.add_argument("--host", required=True, help="public hostname or IP of this server")
    gen.add_argument("--cert", default="chute-cert.pem")
    gen.add_argument("--key", default="chute-key.pem")

    gen_token = sub.add_parser("gen-token", help="generate a fresh random token")
    gen_token.add_argument(
        "--token-file",
        help="create a new private token file instead of printing the token",
    )

    token_hash = sub.add_parser("hash-token", help="print a policy-file token_sha256 verifier")
    token_hash.add_argument(
        "--token-file",
        required=True,
        help="private token file to hash (must be owned by this user and chmod 600 on POSIX)",
    )

    validate_policy = sub.add_parser("validate-policy", help="validate a static policy file")
    validate_policy.add_argument(
        "--policy-file",
        default=_env("CHUTE_POLICY_FILE"),
        help="static policy file to validate (env CHUTE_POLICY_FILE)",
    )

    run = sub.add_parser("run", help="run the server (default)")
    _add_run_args(run)

    args = p.parse_args(raw)
    if args.cmd == "run":
        _apply_run_defaults(args)

    if args.cmd == "gen-cert":
        certs.generate(args.host, Path(args.cert), Path(args.key))
        print(f"wrote {args.cert} and {args.key}  (valid 10 years)")
        print(f"copy {args.cert} to the client and pass it as --server-cert")
        return 0

    if args.cmd == "gen-token":
        token = secrets.token_urlsafe(32)
        if args.token_file:
            try:
                write_new_private_text_file(args.token_file, token, "--token-file")
            except ValueError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
            print(f"wrote token file: {args.token_file}")
            return 0
        print(token)
        return 0

    if args.cmd == "hash-token":
        try:
            token = _read_secret_file(args.token_file, "--token-file")
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(f"sha256:{token_sha256(token)}")
        return 0

    if args.cmd == "validate-policy":
        if not args.policy_file:
            print("error: --policy-file is required (or set CHUTE_POLICY_FILE)", file=sys.stderr)
            return 2
        try:
            validate_static_policy_file(args.policy_file)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(f"policy file ok: {args.policy_file}")
        return 0

    return _run_server(args)


def _add_run_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--token", default=argparse.SUPPRESS)
    p.add_argument("--public-host", default=argparse.SUPPRESS)
    p.add_argument("--public-port", type=int, default=argparse.SUPPRESS)
    p.add_argument("--control-host", default=argparse.SUPPRESS)
    p.add_argument("--control-port", type=int, default=argparse.SUPPRESS)
    p.add_argument(
        "--public-url",
        default=argparse.SUPPRESS,
        help="URL shown to the agent (e.g. http://tunnel.example.com/)",
    )
    # Host-routed labels: route by Host under this base domain and hand each agent
    # a <label>.<base-domain> URL. Typically paired with --upstream-tls behind nginx.
    p.add_argument(
        "--base-domain",
        default=argparse.SUPPRESS,
        help="enable Host-routed labels under this domain (e.g. chute.sh)",
    )
    p.add_argument(
        "--upstream-tls",
        action="store_true",
        default=argparse.SUPPRESS,
        help="TLS is terminated upstream (e.g. nginx); advertise https:// URLs",
    )
    p.add_argument(
        "--cert",
        default=argparse.SUPPRESS,
        help="control-channel cert (pinned self-signed)",
    )
    p.add_argument("--key", default=argparse.SUPPRESS, help="control-channel key")
    # Public HTTPS (optional): a browser-trusted cert, renewed out-of-band by an
    # external ACME tool (lego/certbot). chute loads + hot-reloads these files.
    p.add_argument(
        "--tls-cert",
        default=argparse.SUPPRESS,
        help="public TLS cert (fullchain PEM) -- enables https tunnels",
    )
    p.add_argument("--tls-key", default=argparse.SUPPRESS, help="public TLS private key (PEM)")
    p.add_argument("--tls-port", type=int, default=argparse.SUPPRESS)
    p.add_argument(
        "--policy-file",
        default=argparse.SUPPRESS,
        help=(
            "local StaticPolicyControlPlane JSON file "
            "(env CHUTE_POLICY_FILE; mutually exclusive with CHUTE_CONTROL_PLANE "
            "and CHUTE_AUTHORIZER)"
        ),
    )
    p.add_argument(
        "--event-log-file",
        default=argparse.SUPPRESS,
        help=(
            "local owner-only JSONL EventSink file "
            "(env CHUTE_EVENT_LOG_FILE; mutually exclusive with CHUTE_EVENT_SINK)"
        ),
    )
    p.add_argument(
        "--event-log-max-bytes",
        type=_optional_event_log_max_bytes_arg,
        default=argparse.SUPPRESS,
        help=(
            "rotate the built-in JSONL event log after this many bytes "
            "(env CHUTE_EVENT_LOG_MAX_BYTES; 0/off/none/false/unlimited disables)"
        ),
    )
    p.add_argument(
        "--event-log-backups",
        type=_nonnegative_int_arg,
        default=argparse.SUPPRESS,
        help=(
            "number of rotated built-in JSONL event logs to keep "
            "(env CHUTE_EVENT_LOG_BACKUPS; 0 disables rotation)"
        ),
    )
    p.add_argument(
        "--max-control-conns",
        type=_nonnegative_int_arg,
        default=argparse.SUPPRESS,
        help=(
            "max concurrent pre-auth control handshakes "
            "(env CHUTE_MAX_CONTROL_CONNS; 0 rejects all)"
        ),
    )
    p.add_argument(
        "--max-auth-conns",
        type=_optional_nonnegative_int_arg,
        default=argparse.SUPPRESS,
        help=(
            "max concurrent control-plane/auth calls "
            "(env CHUTE_MAX_AUTH_CONNS; default follows --max-control-conns; 0 rejects all)"
        ),
    )
    p.add_argument(
        "--max-agents",
        type=_nonnegative_int_arg,
        default=argparse.SUPPRESS,
        help="max concurrently registered agent labels (env CHUTE_MAX_AGENTS; 0 rejects all)",
    )
    p.add_argument(
        "--max-visitors",
        type=_nonnegative_int_arg,
        default=argparse.SUPPRESS,
        help="max concurrent public visitor connections (env CHUTE_MAX_VISITORS; 0 rejects all)",
    )
    p.add_argument(
        "--max-visitors-per-ip",
        type=_optional_positive_int_arg,
        default=argparse.SUPPRESS,
        help=(
            "max concurrent direct non-loopback public connections per peer IP "
            "(env CHUTE_MAX_VISITORS_PER_IP; 0/off/none/false/unlimited disables)"
        ),
    )
    p.add_argument(
        "--hello-timeout",
        type=_positive_float_arg,
        default=argparse.SUPPRESS,
        help="seconds allowed for pre-auth handshakes (env CHUTE_HELLO_TIMEOUT)",
    )
    p.add_argument(
        "--auth-timeout",
        type=_positive_float_arg,
        default=argparse.SUPPRESS,
        help="seconds allowed for control-plane/auth calls (env CHUTE_AUTH_TIMEOUT)",
    )
    p.add_argument(
        "--relay-idle-timeout",
        type=_optional_positive_float_arg,
        default=argparse.SUPPRESS,
        help=(
            "seconds without relayed bytes before resetting a visitor stream "
            "(env CHUTE_RELAY_IDLE_TIMEOUT; 0/off/none/false/unlimited disables)"
        ),
    )
    p.add_argument(
        "--mux-flow-window",
        type=_flow_window_arg,
        default=argparse.SUPPRESS,
        help="preferred mux flow-control window in bytes (env CHUTE_MUX_FLOW_WINDOW)",
    )
    p.add_argument(
        "--metrics-host",
        default=argparse.SUPPRESS,
        help="loopback host for optional health/metrics listener (env CHUTE_METRICS_HOST)",
    )
    p.add_argument(
        "--metrics-port",
        type=_optional_metrics_port_arg,
        default=argparse.SUPPRESS,
        help=(
            "enable optional loopback health/metrics listener on this port (env CHUTE_METRICS_PORT)"
        ),
    )
    p.add_argument(
        "--domain",
        default=argparse.SUPPRESS,
        help="public hostname for the https URL (e.g. app.example.com)",
    )
    p.add_argument("-v", "--verbose", action="store_true", default=argparse.SUPPRESS)


def _apply_run_defaults(args: argparse.Namespace) -> None:
    defaults = (
        ("token", lambda: _env("CHUTE_TOKEN")),
        ("public_host", lambda: _env("CHUTE_PUBLIC_HOST", "0.0.0.0")),
        ("public_port", lambda: _int_env("CHUTE_PUBLIC_PORT", 80)),
        ("control_host", lambda: _env("CHUTE_CONTROL_HOST", "0.0.0.0")),
        ("control_port", lambda: _int_env("CHUTE_CONTROL_PORT", 7000)),
        ("public_url", lambda: _env("CHUTE_PUBLIC_URL")),
        ("base_domain", lambda: _env("CHUTE_BASE_DOMAIN")),
        ("upstream_tls", lambda: _env_bool("CHUTE_UPSTREAM_TLS")),
        ("cert", lambda: _env("CHUTE_CERT", "chute-cert.pem")),
        ("key", lambda: _env("CHUTE_KEY", "chute-key.pem")),
        ("tls_cert", lambda: _env("CHUTE_TLS_CERT")),
        ("tls_key", lambda: _env("CHUTE_TLS_KEY")),
        ("tls_port", lambda: _int_env("CHUTE_TLS_PORT", 443)),
        (
            "max_control_conns",
            lambda: _nonnegative_int_env("CHUTE_MAX_CONTROL_CONNS", _DEFAULT_MAX_CONTROL_CONNS),
        ),
        ("max_auth_conns", lambda: _optional_nonnegative_int_env("CHUTE_MAX_AUTH_CONNS")),
        ("max_agents", lambda: _nonnegative_int_env("CHUTE_MAX_AGENTS", _DEFAULT_MAX_AGENTS)),
        (
            "max_visitors",
            lambda: _nonnegative_int_env("CHUTE_MAX_VISITORS", _DEFAULT_MAX_VISITORS),
        ),
        (
            "max_visitors_per_ip",
            lambda: _optional_positive_int_env(
                "CHUTE_MAX_VISITORS_PER_IP", _DEFAULT_MAX_VISITORS_PER_IP
            ),
        ),
        (
            "hello_timeout",
            lambda: _positive_float_env("CHUTE_HELLO_TIMEOUT", _DEFAULT_HELLO_TIMEOUT),
        ),
        ("auth_timeout", lambda: _positive_float_env("CHUTE_AUTH_TIMEOUT", _DEFAULT_AUTH_TIMEOUT)),
        (
            "relay_idle_timeout",
            lambda: _optional_positive_float_env(
                "CHUTE_RELAY_IDLE_TIMEOUT", _DEFAULT_RELAY_IDLE_TIMEOUT
            ),
        ),
        ("mux_flow_window", lambda: _flow_window_env("CHUTE_MUX_FLOW_WINDOW")),
        ("metrics_host", lambda: _env("CHUTE_METRICS_HOST", "127.0.0.1")),
        ("metrics_port", lambda: _optional_positive_int_env("CHUTE_METRICS_PORT", None)),
        ("policy_file", lambda: _env("CHUTE_POLICY_FILE")),
        ("event_log_file", lambda: _env("CHUTE_EVENT_LOG_FILE")),
        (
            "event_log_max_bytes",
            lambda: _optional_positive_int_env(
                "CHUTE_EVENT_LOG_MAX_BYTES", DEFAULT_JSONL_EVENT_LOG_MAX_BYTES
            ),
        ),
        (
            "event_log_backups",
            lambda: _nonnegative_int_env(
                "CHUTE_EVENT_LOG_BACKUPS", DEFAULT_JSONL_EVENT_LOG_BACKUPS
            ),
        ),
        ("domain", lambda: _env("CHUTE_DOMAIN")),
        ("verbose", lambda: False),
    )
    for name, default in defaults:
        if not hasattr(args, name):
            setattr(args, name, default())


def _run_server(args: argparse.Namespace) -> int:
    _setup_logging(getattr(args, "verbose", False))

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
    try:
        certs.warn_if_control_cert_expiring(cert)
        ssl_ctx = certs.server_ssl_context(cert, key)
    except (OSError, ValueError, ssl.SSLError) as exc:
        log.error("control TLS cert/key invalid (%s / %s): %s", cert, key, exc)
        return 2

    tls_cert = tls_key = None
    public_https_url = None
    if bool(args.tls_cert) != bool(args.tls_key):
        log.error("set both --tls-cert and --tls-key to enable public TLS")
        return 2
    if args.tls_cert and args.tls_key:
        tc, tk = Path(args.tls_cert), Path(args.tls_key)
        if not (tc.exists() and tk.exists()):
            log.error("public TLS cert/key not found (%s / %s)", tc, tk)
            return 2
        tls_cert, tls_key = tc, tk
        host = args.domain
        if not host and args.public_url:
            host = args.public_url.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
        if not host or host == "0.0.0.0":
            log.error("--domain is required when enabling public TLS")
            return 2
        suffix = "" if args.tls_port == 443 else f":{args.tls_port}"
        public_https_url = f"https://{host}{suffix}/"
    elif args.upstream_tls and not args.base_domain:
        host = args.domain
        if not host and args.public_url:
            host = args.public_url.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
        if not host or host == "0.0.0.0":
            log.error("--domain or --public-url is required for default-route --upstream-tls")
            return 2
        public_https_url = f"https://{host}/"

    try:
        control_plane = _build_control_plane(args.policy_file)
        authorizer = _build_authorizer(args.token or "")
        if control_plane is not None and authorizer is not None:
            log.error(
                "set only one of --policy-file/CHUTE_POLICY_FILE, "
                "CHUTE_CONTROL_PLANE, or CHUTE_AUTHORIZER"
            )
            return 2
        if not args.token and control_plane is None and authorizer is None:
            log.error("--token is required (or set CHUTE_TOKEN)")
            return 2
        server = Server(
            token=args.token or "",
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
            max_control_conns=args.max_control_conns,
            max_agents=args.max_agents,
            max_visitors=args.max_visitors,
            hello_timeout=args.hello_timeout,
            auth_timeout=args.auth_timeout,
            max_auth_conns=args.max_auth_conns,
            authorizer=authorizer,
            control_plane=control_plane,
            event_sink=_build_event_sink(
                args.event_log_file,
                event_log_max_bytes=args.event_log_max_bytes,
                event_log_backups=args.event_log_backups,
            ),
            require_event_sink=_env_bool("CHUTE_REQUIRE_EVENT_SINK"),
            max_visitors_per_ip=args.max_visitors_per_ip,
            relay_idle_timeout=args.relay_idle_timeout,
            mux_flow_window=args.mux_flow_window,
            metrics_host=args.metrics_host,
            metrics_port=args.metrics_port,
        )
    except (OSError, ValueError, ssl.SSLError) as exc:
        # Host routing on a routable bind, invalid public TLS cert/key, and other
        # config-time failures should become a clean service failure, not a traceback
        # followed by a systemd restart loop.
        log.error("server configuration invalid: %s", exc)
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
