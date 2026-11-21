"""pytest glue for the Vendor Audit tests.

The test files also run on their own (python3 tests/test_findings.py).
They record failed checks in a module-level _failures list instead of
stopping at the first one, so a single run reports everything that is
wrong. This hook makes pytest see those recorded failures: any check a
test adds to _failures fails that test, with every message shown.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


@pytest.hookimpl(wrapper=True)
def pytest_pyfunc_call(pyfuncitem):
    failures = getattr(pyfuncitem.module, "_failures", None)
    start = len(failures) if failures is not None else 0
    result = yield
    if failures is not None and len(failures) > start:
        new = failures[start:]
        del failures[start:]
        raise AssertionError("\n" + "\n".join(new))
    return result
