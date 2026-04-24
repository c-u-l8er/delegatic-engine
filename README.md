# delegatic

OS-006 Governance Shim — authorization kernel for the [&] Protocol ecosystem.

Issues signed, expiring `AuthorizationBlock`s to destructive edges in OS-011 `&body.*` replay flows. Policy-based, deny-by-default, pluggable policy store.

## Status

- **Library:** v0.1.0 production-ready
- **Tests:** 42/42 (25 unit + 3 integration + 14 MCP tool tests) + 2 body-os end-to-end integration tests
- **Storage:** in-memory ETS-backed `PolicyStore` — Postgres-backed adapter is a future additive release
- **MCP server:** shipped — 6 tools on the `delegatic` namespace (put/get/list/delete policy + authorize + verify) with Anubis stdio/HTTP transport
- **Deployment:** `fly.toml` + `Dockerfile` ready for Fly.io (`delegatic-mcp`, port 4400)

## MCP surface

```
delegatic_put_policy       — register or replace a Policy
delegatic_get_policy       — look up a Policy by id
delegatic_list_policies    — list every registered Policy
delegatic_delete_policy    — remove a Policy
delegatic_authorize        — issue a fresh AuthorizationBlock
delegatic_verify           — verify a block's HMAC signature + TTL
```

Remote agents (body-browser-mcp, body-os-mcp, FleetPrompt's InstallEngine, Graphonomous replay flows) call `delegatic_authorize` to obtain the fresh blocks they need for destructive edges per OS-011 §4.4.

This is the *authorization kernel* — the minimum needed to close the OS-011 destructive-edge loop. The full Delegatic spec (`delegatic.com/docs/spec/`) layers on org trees, memberships, effective-policy computation, and a LiveView dashboard; those are future work.

## Contract

```elixir
# 1. Register a policy
:ok =
  Delegatic.put_policy(
    Delegatic.Policy.new(%{
      policy_id: "delegatic://ws-42/ops",
      allow_actions: ["file_write", "shell_exec"],
      deny_actions: ["file_delete"],
      agents: ["ops-agent"],
      max_ttl_seconds: 300
    })
  )

# 2. Directly request authorization for one action
{:ok, block} =
  Delegatic.authorize(
    action_type: "file_write",
    policy_id: "delegatic://ws-42/ops",
    agent_id: "ops-agent",
    approved_by: "supervisor@acme"
  )

# 3. Or build a function ready for the OS-011 Replay `:authorizer` slot
authorizer =
  Delegatic.authorizer_for(
    policy_id: "delegatic://ws-42/ops",
    approved_by: "supervisor@acme",
    agent_id: "ops-agent"
  )

# 4. Wire it into body-os replay
BodyOs.Replay.execute(session, trace, authorizer: authorizer)
```

## AuthorizationBlock

Every issued block carries:

| Field                 | Example                                     |
|-----------------------|---------------------------------------------|
| `policy_id`           | `"delegatic://ws-42/ops"`                   |
| `approved_by`         | `"supervisor@acme"`                         |
| `approved_at`         | ISO8601 UTC                                 |
| `expires_at`          | ISO8601 UTC (capped at `policy.max_ttl_seconds`) |
| `authorization_token` | `"sha256:<64-hex>"` — HMAC over the other fields |

The token is *tamper-evident*, not secret — any consumer can call `Delegatic.AuthorizationBlock.verify/1` to detect forgery or expiration.

The HMAC key lives in `config :delegatic, :hmac_key`. A per-process random fallback is used when unset (fine for tests, unsafe for prod).

## Policy semantics

1. **`action in deny_actions`** → `{:error, :denied_by_policy}`
2. **`agents` set and `agent_id` not in it** → `{:error, :agent_not_allowed}`
3. **`action not in allow_actions`** → `{:error, :not_in_allowlist}` (deny-by-default)
4. Otherwise → `:ok`

## Wiring Delegatic into OS-011 replay

The OS-011 spec §4.4 requires that every destructive replay edge obtain a *fresh* authorization — prior authorization does not carry. Delegatic's `authorizer_for/1` returns a function that re-issues a new block on every call, producing exactly the semantics OS-011 demands:

```elixir
# Recorded trace: destructive edges carry OLD authorization blocks
# Replay stripper: body-os.Replay strips them before dispatch
# Delegatic authorizer: fresh block for every edge that makes it through policy
# Session: enforces the destructive-action gate on the fresh block
```

See `body-os/test/delegatic_integration_test.exs` for the end-to-end test that exercises this flow — both the success path (allowlist policy → replay succeeds) and the failure path (readonly policy → replay halts with `reason: "authorization_failure"`).

## Running the suite

```
mix deps.get
mix test
```

## References

- `delegatic.com/docs/spec/README.md` — full v0.2 spec (organizations, memberships, effective policy, dashboard)
- `opensentience.org/docs/spec/OS-011-EMBODIMENT.md` §4.4 — AuthorizationBlock contract
- `body-os/` + `body-browser/` — OS-011 providers whose Replay flows consume Delegatic authorizers

## License

Apache-2.0
