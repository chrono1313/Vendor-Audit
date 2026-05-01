"""Vendor Audit — passive domain security and maturity audit.

Package entry point. The heavy imports (dnspython, requests, httpx, etc.)
live inside the submodules and are only loaded when the CLI actually runs,
so `import vendor_audit` stays cheap.
"""

# Mirrors cli.__version__. The cross-module version sanity check inside cli.py
# is the source of truth; this constant is just a convenience for tooling that
# inspects vendor_audit.__version__.
__version__ = "1.0"


def main():
    """Console-script entry point.

    Imported lazily so that `import vendor_audit` doesn't pay the cost of
    pulling in dnspython / requests / httpx / tldextract.
    """
    from .cli import main as _main
    return _main()
