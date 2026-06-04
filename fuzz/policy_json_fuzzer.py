from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports():
    from fuzz._targets import check_policy_json


def TestOneInput(data: bytes) -> None:
    check_policy_json(data)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
