#!/usr/bin/env python3
import sys

if __name__ == "__main__":
    """
    Optional: allow `./runner.py` to behave as a pytest wrapper.

    Examples:
        ./runner.py -q
        ./runner.py tests/test_namespaces.py::test_namespace_create_valid
    """
    import pytest

    sys.exit(pytest.main(sys.argv[1:]))