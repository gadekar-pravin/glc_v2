"""Setup utilities for the Microsoft Teams adapter.

These are operator-facing tools that run outside the agent runtime:

- ``emulator_runner`` — local aiohttp stub server (``POST /api/messages``)
  for driving the adapter with curl or the Bot Framework Emulator.
  Run via ``python -m glc.channels.catalogue.teams.setup.emulator_runner``.

- ``trust_setup`` — operator CLI that manages Teams pairings through the
  authenticated gateway control plane. It never opens the pairing database.
"""

from __future__ import annotations
