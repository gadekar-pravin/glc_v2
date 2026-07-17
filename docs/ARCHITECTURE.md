# GLC v1 architecture

Session 11 §7 names six architectural moves that distinguish GLC v1
from OpenClaw's default posture. Each is a direct response to a
documented OpenClaw failure mode. The mapping below names the move,
where it lives in this repository, and which incident it answers.

## 1. The agent does not get host execution authority by default

The runtime is the S9 multi-agent DAG plus the typed skill catalogue.
Tools live as named typed handlers; there is no generic `shell.exec`
endpoint that the agent can reach by default. Channel adapters speak
typed Pydantic envelopes (`ChannelMessage`, `ChannelReply`) — they
never hand a Discord embed or a Telegram InputFile to the agent.

Lives in: `glc/channels/envelope.py`, `glc/channels/base.py`.
Answers: ClawJacked.

## 2. The policy engine runs in a separate process

`glc/policy/engine.py` is a pure declarative evaluator. The gateway never imports it as an
enforcement entry point. During FastAPI startup, `ProcessPolicyClient` launches a clean child
interpreter running `glc.policy.worker` and communicates over request-ID-bound JSON lines on private
stdin/stdout pipes. Rules are specified in `glc/policy/policy.yaml` (or `~/.glc/policy.yaml` to
override). First matching rule wins; ties resolve to deny. The defaults for `owner_paired` and
`untrusted` are allow and deny respectively.

The worker independently loads the policy file and receives no provider, control-plane, signing, or
slot-identity secrets. A missing, timed-out, crashed, or malformed worker fails closed with a deny
verdict and makes `/healthz` return HTTP 503. `SIGHUP` is forwarded to the worker for hot reload. The
current S11 channel agent remains an echo stub; its eventual tool dispatcher must use the
lifespan-owned client rather than instantiate `PolicyEngine` in the gateway.

Lives in: `glc/policy/`, lifecycle wiring in `glc/main.py`.
Answers: the Summer Yue email-deletion incident, where the "confirm
before acting" rule lived inside the conversation context and was
erased by context compaction. Yaml does not compact.

## 3. Memory is classed with per-class write permissions

The audit store (`glc/audit/`) is database-enforced append-only. Its
SQLite schema rejects `UPDATE` and `DELETE`, and every row is linked to
the SHA-256 hash of its predecessor. The pairing store and Volume are
mounted only in the gateway; adapter images do not contain pairing code.
The channels configuration and policy rules also live outside the LLM's
write reach. Sessions 12 and onward expand the memory taxonomy to working /
episodic / semantic / procedural classes; the write-permission
discipline begins here.

Lives in: `glc/audit/`, `glc/security/pairing.py`, `glc/config.py`.
Answers: persistent-prompt-injection attacks that would otherwise
mutate the agent's own constraints.

## 4. The control plane has an out-of-band path

`/v1/control/kill`, `/v1/control/pair`, `/v1/control/presence` are
authenticated by a per-installation token. Production receives it as the
gateway-only `GLC_INSTALL_TOKEN` container Secret; adapter containers receive
neither that environment variable nor the gateway Volume. Local development
retains `~/.glc/install_token` for CLI compatibility. The kill endpoint binds
127.0.0.1 by default; bypassing this requires `GLC_KILL_ALLOW_REMOTE=1`
and a deliberate operator decision. The intent is to make "STOP"
reachable through a phone-friendly URL the user can hit when the
agent has gone off the rails inside the channel.

Lives in: `glc/routes/control.py`.
Answers: Summer Yue having to physically reach the Mac mini.

## 5. Every channel envelope carries a trust level

`TrustLevel` is `owner_paired | user_paired | untrusted`. Adapters send
an untrusted `ChannelIngress`; the gateway normalizes its channel to the
authenticated slot and classifies the sender via `glc/security/trust_level.py`,
which consults the gateway-only pairing store. Legacy adapter claims are
accepted for wire compatibility but ignored. The policy engine reads the trust level
before authorising any tool action; the lecture's default rule
denies all tools for `untrusted`.

Lives in: `glc/channels/envelope.py`, `glc/routes/channels.py`,
`glc/security/trust_level.py`, `glc/policy/`.
Answers: confused-deputy and indirect-prompt-injection. An email
scraped from the inbox can carry instructions, but it arrives with
`trust_level=untrusted` and the policy engine rejects everything.

## 6. Every action is logged append-only

`glc/audit/store.py` writes to `~/.glc/audit.sqlite`. Each row carries
session id, channel, sender id, trust level, event type, tool, policy
verdict, params, result, the previous hash, and its own entry hash. A
canonical SHA-256 chain binds the row ID and every stored field to its
predecessor. SQLite triggers reject direct updates and deletes, and
startup fails closed if the schema, triggers, or chain do not verify.
Each append uses an immediate transaction and commits before returning,
so concurrent writes serialize and the trail survives a hard kill.

Schema-v1 databases migrate in place before the gateway starts. The
transactional migration preserves existing rows and the AUTOINCREMENT
high-water mark while backfilling the chain. On Modal, the persistent
volume containing the audit database is attached only to the gateway
function; isolated channel and external voice slots cannot mount it.

Lives in: `glc/audit/`.
Answers: the recovery scenario after a bad outcome — the operator
can replay exactly what the agent saw and did.

## What S12 works on

The S11 policy engine is the application-level enforcement layer.
S12 moves this gateway onto Modal containers and then hardens it. The
environmental layer it needs, container isolation per component,
short-lived scoped credentials in place of one shared secret, and
network egress filters, is not built yet. Building it is the
assignment. The two layers should run independently, so that a
failure in one does not invalidate the other.
