"""Allow ``python -m src`` (in a clone) and ``python -m terradrift`` (when installed)."""

from .cli import main

raise SystemExit(main())
