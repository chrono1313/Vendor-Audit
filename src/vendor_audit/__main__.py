"""Allow `python -m vendor_audit ...` as an alternative to the `vendor-audit`
console script."""

from .cli import main

if __name__ == "__main__":
    main()
