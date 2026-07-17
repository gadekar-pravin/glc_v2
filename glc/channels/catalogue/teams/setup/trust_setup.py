"""Operator CLI for managing Teams pairings through the gateway control plane.

This utility never opens the pairing database.  Supply an installation token
explicitly (or with ``GLC_INSTALL_TOKEN``) and it calls the authenticated
gateway API.  Adapter containers are not given that token.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from typing import Any

import httpx

CHANNEL = "teams"


def _headers(args: argparse.Namespace) -> dict[str, str]:
    token = (args.token or os.getenv("GLC_INSTALL_TOKEN", "")).strip()
    if not token:
        raise ValueError("provide --token or set GLC_INSTALL_TOKEN")
    return {"Authorization": f"Bearer {token}"}


def _url(args: argparse.Namespace, path: str) -> str:
    return f"{args.gateway.rstrip('/')}{path}"


def _request(args: argparse.Namespace, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
    response = httpx.request(method, _url(args, path), headers=_headers(args), timeout=15.0, **kwargs)
    if response.status_code >= 400:
        raise RuntimeError(f"gateway returned HTTP {response.status_code}: {response.text}")
    return response.json()


def cmd_invite(args: argparse.Namespace) -> int:
    result = _request(
        args,
        "POST",
        "/v1/control/pair",
        json={
            "channel": CHANNEL,
            "channel_user_id": args.user_id,
            "user_handle": args.handle or "",
            "trust_level": args.trust,
        },
    )
    print(f"Pairing code for {args.user_id!r}: {result['code']}")
    print(f"Confirm with: trust_setup --token <token> confirm {result['code']}")
    return 0


def cmd_confirm(args: argparse.Namespace) -> int:
    result = _request(args, "POST", "/v1/control/pair/confirm", json={"code": args.code})
    if result.get("channel") != CHANNEL:
        raise RuntimeError(f"code belongs to channel {result.get('channel')!r}")
    print(f"Confirmed {result['channel_user_id']!r} as {result['trust_level']} on channel {CHANNEL!r}.")
    return 0


def cmd_owner(args: argparse.Namespace) -> int:
    args.trust = "owner_paired"
    result = _request(
        args,
        "POST",
        "/v1/control/pair",
        json={
            "channel": CHANNEL,
            "channel_user_id": args.user_id,
            "user_handle": args.handle or "owner",
            "trust_level": "owner_paired",
        },
    )
    args.code = result["code"]
    return cmd_confirm(args)


def cmd_list(args: argparse.Namespace) -> int:
    result = _request(args, "GET", "/v1/control/presence")
    pairings = [p for p in result.get("paired_users", []) if p.get("channel") == CHANNEL]
    if not pairings:
        print("No Teams pairings.")
        return 0
    for pairing in pairings:
        print(
            f"{pairing['channel_user_id']:<24} {pairing['trust_level']:<14} "
            f"handle={pairing.get('user_handle') or '-'}"
        )
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="trust_setup", description=__doc__)
    parser.add_argument("--gateway", default=os.getenv("GLC_GATEWAY_URL", "http://127.0.0.1:8111"))
    parser.add_argument("--token", help="gateway installation token (prefer a shell prompt variable)")
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    owner = subparsers.add_parser("owner", help="pair an owner through authenticated pair/confirm")
    owner.add_argument("user_id")
    owner.add_argument("--handle", default=None)
    owner.set_defaults(func=cmd_owner)

    invite = subparsers.add_parser("invite", help="issue a six-digit pairing code")
    invite.add_argument("user_id")
    invite.add_argument("--handle", default=None)
    invite.add_argument("--trust", choices=("user_paired", "owner_paired"), default="user_paired")
    invite.set_defaults(func=cmd_invite)

    confirm = subparsers.add_parser("confirm", help="confirm a pairing code")
    confirm.add_argument("code")
    confirm.set_defaults(func=cmd_confirm)

    listing = subparsers.add_parser("list", help="list Teams pairings through presence")
    listing.set_defaults(func=cmd_list)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except (ValueError, RuntimeError, httpx.HTTPError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
