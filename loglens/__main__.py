import sys

from .cli import main

try:
    sys.exit(main())
except BrokenPipeError:  # e.g. `python -m loglens x.log | head`
    sys.exit(0)
