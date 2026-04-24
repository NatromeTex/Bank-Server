#!/usr/bin/env python3
"""
Mitigation Controller — entry point.

Run from the project root:
    python mitigation/app.py

Or with shadow mode (log-only, no actual IP blocking):
    SHADOW=1 python mitigation/app.py
"""
import asyncio
import os
import sys
from pathlib import Path

# Ensure project root is on the path regardless of where this is invoked from
sys.path.insert(0, str(Path(__file__).parent.parent))

from mitigation.config import MitigationConfig
from mitigation.controller import MitigationController

if __name__ == "__main__":
    config = MitigationConfig()

    # Allow shadow mode via environment variable
    if os.environ.get("SHADOW", "").strip() in ("1", "true", "yes"):
        config.enforcement_mode = False
        print("[MITIGATION] Running in SHADOW mode — logging only, no IP enforcement")
    else:
        print("[MITIGATION] Running in ENFORCEMENT mode — bank middleware will block IPs")

    controller = MitigationController(config)
    asyncio.run(controller.run())
