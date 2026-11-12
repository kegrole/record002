"""Allow ``python -m xssscan`` as well as ``python -m xssscan.cli``."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
