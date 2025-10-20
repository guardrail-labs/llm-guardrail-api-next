#!/usr/bin/env python3
"""Entrypoint ensuring /tmp exists for read-only filesystems."""

import os
import sys

os.makedirs("/tmp", exist_ok=True)

if len(sys.argv) <= 1:
    raise SystemExit("No command provided to entrypoint")

os.execvp(sys.argv[1], sys.argv[1:])
