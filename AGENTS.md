# AGENTS.md

This file provides guidance to both Claude Code (claude.ai/code) and Codex (Codex.ai/code) when working with code in this repository.

## What this repo is

`glc_v2` is the **GLC gateway** (a FastAPI service fronting multiple LLM providers and
messaging/voice channels) serving as the **Session 12 Part-2 reference target** for the EAG3
course. It is the shared repo that students open bug-hunt pull requests against.

**The security flaws in this codebase are intentional and left in on purpose** (see `README.md`,
`ASSIGNMENT.md`, `docs/ARCHITECTURE.md`). Do NOT treat them as accidental bugs to silently fix or
refactor away — they are the bug-hunt targets. When you spot a flaw, surface it; only change it if
the user is deliberately fixing that specific issue. Use **mock/placeholder API keys only** — the
brief forbids real provider keys (especially on Modal).

## Commands

Uses **`uv`** (there is a committed `uv.lock`) — never `pip`.

- `uv sync` — install deps
- `uv run glc serve` — run the gateway on http://localhost:8111 (`glc` CLI also has `token`, `channels`)
- `uv run modal deploy modal_app.py` — deploy via Modal

Tests / lint / type-check (these mirror `.github/workflows/ci.yml`):

- Full test suite — note the non-standard marker filter, ignored dirs, and 80% coverage gate:
  ```
  uv run pytest tests/ -m "not requires_live_api and not requires_models" \
    --ignore=tests/channels --ignore=tests/voice/stt --ignore=tests/voice/tts \
    --cov=glc --cov-report=term-missing --cov-fail-under=80
  ```
  `requires_live_api` (real provider keys) and `requires_models` (local Kokoro/whisper.cpp) are
  skipped in CI. `pytest` runs in `asyncio_mode = "auto"` (no `@pytest.mark.asyncio` needed).
- `uv run ruff check .` and `uv run ruff format --check .` — lint / format check
- `uv run mypy glc tests` — type check (non-strict; advisory in CI)
- `uv run python scripts/validate_envelope.py` and `uv run python scripts/validate_policy.py` — schema gates

## Code style

- ruff `line-length = 110` (not 88); `E501` and `B008` are ignored.
- **V9-ported modules** (`glc/providers.py`, `glc/routes/chat.py`, `glc/embedders.py`,
  `glc/routing.py`, `glc/cache.py`, `glc/pricing.py`, etc.) are kept **verbatim from llm_gatewayV9**
  and have per-file ruff ignores (`B023, B904, F841`). Don't reformat or "clean up" these — it
  re-introduces the V9 bugs the ignores exist to preserve.

## Gotchas

- Config/state lives in `~/.glc/` (audit/pairings/gateway SQLite DBs). **`GLC_CONFIG_DIR` overrides
  the location** — tests, CI, and Modal set it. `glc/config.py` creates the dir on import.
- No `.env.example` exists; `glc/main.py` auto-loads a repo-root `.env` if present. Most secrets are
  read from env at runtime and are provider-gated (all optional).
- `~/.glc/install_token` gates the control plane (`/v1/control/*`) and channel WS/webhook auth.
  `/v1/control/kill` is loopback-only unless `GLC_KILL_ALLOW_REMOTE=1`.
- The policy engine hot-reloads on `SIGHUP` (`kill -HUP <pid>`); malformed `policy.yaml` fails closed
  (deny-everything).
- The WS/webhook agent path is a **stub** — it echoes `[glc echo] <text>` back; the
  `require_approval` confirmation loop is not implemented.
- `scripts/check_pr_boundaries.py` and `scripts/scorecard.py` read `GROUPS.md`/`CLAIMS.md`, and
  CODEOWNERS/pyproject reference an `adapter-pr.yml` workflow — **none of these exist on this
  branch** (they live in the `scoreboard-scaffold` branch). Expect missing-file errors if run here.

## PR conventions

- Default branch is `main`; commit subjects are capitalized imperative, sometimes with a `glc_v2:` scope prefix.
- PRs follow `.github/PULL_REQUEST_TEMPLATE.md`: describe the bug, name the **invariant broken**
  (one of Session 12 §4's eight), and give a **reproduction that runs from a fresh checkout**.
- A PR must only touch its claimed slot's paths (enforced by `scripts/check_pr_boundaries.py`).
  All review routes to `@theschoolofai` (see `.github/CODEOWNERS`).
