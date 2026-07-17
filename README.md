# glc_v2 — Session 12 reference repository

This is the reference repository for **Part 2** of the Session 12 assignment. It is the glc gateway (the Session 11 `glc_v1` code plus the Modal wrapper `modal_app.py`), left with its security flaws in place on purpose. It is the shared target you open pull requests against when you find a new bug.

## The assignment in one screen

- **Part 1 (required), on your own clone of `glc_v1`.** Migrate it to Modal as Section 6 of the session walks it, then fix every finding in Sections 6 and 7. You submit your hardened repository. This part does not happen here.
- **Part 2 (100 points per new bug), here.** Find a bug that Sections 6 and 7 do not already name, and open a pull request against this repository that describes it, reproduces it from a fresh checkout, and fixes it. The pull-request template walks you through the four things it needs. On duplicates, the first pull request filed wins, so check the open pull requests first.

The full brief is in [`ASSIGNMENT.md`](ASSIGNMENT.md).

## Run it

This is a `uv` project.

```sh
uv sync
uv run glc serve        # gateway on http://localhost:8111
```

To deploy on Modal, see `modal_app.py` and Session 12 Section 6. Use mock keys only, and never put real provider keys on Modal.

The hardened deployment separates channel and external voice slots from the gateway. Its 22-slot
least-privilege manifest, single-use tool credential flow, Telegram reference deployment, and safe
proof command are documented in [`docs/SLOT_ISOLATION.md`](docs/SLOT_ISOLATION.md). Channel slots do
not receive `glc-llm-keys` or the installation token.

The Modal wrapper runs with `GLC_ENV=production`. Production disables `/openapi.json`, `/docs`, and
`/redoc`, and every HTTP request requires the gateway-only installation token. Create a random token,
keep the operator copy in a password manager, and bind it only to the gateway's Modal Secret:

```sh
uv run modal secret create glc-install-token GLC_INSTALL_TOKEN=<random-install-token>
curl -H "Authorization: Bearer <random-install-token>" \
  https://<workspace>--glc-v1-gateway-fastapi-app.modal.run/healthz
```

Production refuses to start without a non-empty `GLC_INSTALL_TOKEN`; it never reads
`GLC_CONFIG_DIR/install_token`. Local development remains file-backed, so `uv run glc token` keeps
working unchanged. Never attach `glc-install-token` to an adapter or voice-slot function.

Gateway channel webhook URLs are disabled in every mode. Provider callbacks terminate in isolated
slot runtimes, which authenticate to the gateway WebSocket with their slot identity.

Configuration and operational read endpoints require the installation token in every environment,
including local development: `/v1/embedders`, `/v1/cost/by_agent`, `/v1/providers`,
`/v1/capabilities`, `/v1/status`, `/v1/routers`, and `/v1/calls`. For example:

```sh
curl -H "Authorization: Bearer $(uv run glc token)" http://localhost:8111/v1/status
```

Remote images used by `/v1/chat` and `/v1/vision` are disabled by default. To enable specific image
hosts, set `GLC_IMAGE_URL_ALLOWED_HOSTS` to a comma-separated list of exact hostnames (for example,
`images.example.com,cdn.example.com`). Each host must also resolve exclusively to publicly routable
IPv4 or IPv6 addresses, and the allowlist and addresses are checked again after every redirect.
Inline `data:` image URLs do not require an allowlist entry.

## Where to look

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — trust boundaries and data flows. Start here for recon.
- `glc/` — the gateway source.
- `modal_app.py` — the Modal deployment wrapper.
- Local-only `/openapi.json` and `/docs` — disabled on production deployments.

## License

MIT, see [`LICENSE`](LICENSE).
