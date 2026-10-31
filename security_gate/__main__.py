"""Allow the gate to run as ``python -m security_gate``."""

import sys

from security_gate.cli import main

if __name__ == "__main__":
    sys.exit(main())
