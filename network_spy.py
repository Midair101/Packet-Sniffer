#!/usr/bin/env python3
"""
Top-level shim: the project code is now in the `network_spy` package.
Run `python network_spy.py` to start the CLI (delegates to package).
"""
from network_spy.core import main

if __name__ == '__main__':
    main()
