"""Entry point: ``python main.py`` (interactive wallet) or ``python main.py --demo``."""

import sys

from credential_sharing.cli import main

if __name__ == "__main__":
    sys.exit(main())
