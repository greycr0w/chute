from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports():
    from fuzz._targets import check_protocol_decode


def TestOneInput(data: bytes) -> None:
    check_protocol_decode(data)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
