# Policy guide

The policy engine is the deterministic safety layer that runs in a dedicated child process, outside
the gateway interpreter and LLM context. Lecture §10 documents the five default rules; this guide
explains how to extend them.

## Where policy lives

`glc/policy/policy.yaml` ships with the lecture's five defaults. To
override on your installation, drop a `policy.yaml` into `~/.glc/`.
The engine prefers the user file when present.

The gateway starts `glc.policy.worker` during FastAPI lifespan and communicates with it through a
validated JSON-lines protocol. The child loads policy independently and receives no gateway
credentials. If it stops answering, policy evaluation denies by default and `/healthz` returns HTTP
503 until the gateway restarts.

Hot-reload by sending `SIGHUP` to the gateway process. The gateway forwards the reload request to
the child:

```sh
kill -HUP $(pgrep -f "uv run glc serve")
```

Malformed YAML does not crash the gateway: the engine falls back to
a deny-everything safe default and logs the parse error.

Production gateway code must use the lifespan-owned `app.state.policy_client`. Importing or
instantiating `PolicyEngine` outside `glc.policy` is forbidden by a regression test.

## Rule shape

```yaml
rules:
  - tool: email.send                # literal or "*"
    channel: telegram               # literal or "*" (default "*")
    trust_level: owner_paired       # literal or "*" (default "*")
    condition:
      recipient_type: external      # exact match
      path_glob: "~/Documents/**"   # fnmatch glob
      command_matches: ["sudo"]     # substring (any-match if list)
      foo_regex: "^bad-.*$"         # re.search
      something_in: ["a", "b"]      # set membership
    action: deny                    # allow | deny | require_approval
    reason: "external recipient requires approval"
```

## Evaluation order

For each tool call, the engine walks rules top to bottom:

1. The first rule whose `tool` / `channel` / `trust_level` / `condition`
   all match determines the verdict.
2. If any matching rule has `action: deny`, that overrides — deny
   wins on ties.
3. If no rule matches, the default is `allow` when `trust_level ==
   owner_paired`, otherwise `deny`.

This means: a permissive `tool: "*", action: allow` rule at the top
makes the engine essentially open for everyone whose `trust_level`
makes it through earlier deny rules. Use sparingly.

## `require_approval`

When the verdict is `require_approval`, the agent runtime sends an
approval-request message back through the originating channel and
blocks on confirmation. The S11 runtime stub does not implement the
confirmation loop yet — it will land alongside the S12 agent
runtime work.

## Audit trail

Every verdict is written to `~/.glc/audit.sqlite` as part of the
`tool_dispatch` event row. Use `glc.audit.query()` or open the S8
replay viewer to inspect.

## Testing your policy

```sh
uv run python scripts/validate_policy.py
```

The script loads `policy.yaml` and runs one evaluation per rule. Any
parse error or schema mismatch fails CI.
