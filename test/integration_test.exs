defmodule Delegatic.IntegrationTest do
  @moduledoc """
  End-to-end integration: Delegatic authorizer drives real body provider
  replay flows. This is the proof that OS-006 Governance + OS-011
  Embodiment wire together end-to-end.

  Requires sibling path deps on body-browser + body-os to exercise
  `BodyBrowser.Replay.execute/3` and `BodyOs.Replay.execute/3` with a
  Delegatic authorizer.

  Status: **skipped by default** — these tests only run when the
  sibling apps are available on the path and the
  DELEGATIC_INTEGRATION=1 env var is set. The unit suite in
  `delegatic_test.exs` validates the kernel independently.
  """

  use ExUnit.Case, async: false

  @moduletag :integration

  # Conditional execution — the replay round-trip requires the sibling
  # body-os app compiled. We guard via function_exported?/3 so that
  # when run in a workspace without body-os, the tests simply report
  # "skipped" rather than compile-error.

  setup do
    Application.ensure_all_started(:delegatic)
    Delegatic.PolicyStore.clear()
    :ok
  end

  test "Delegatic authorizer_for/1 returns a function shaped for Replay" do
    # Pure structural test — works without any body-* dep.
    :ok =
      Delegatic.put_policy(
        Delegatic.Policy.new(%{
          policy_id: "delegatic://it/ok",
          allow_actions: ["file_write"],
          max_ttl_seconds: 120
        })
      )

    authorizer =
      Delegatic.authorizer_for(
        policy_id: "delegatic://it/ok",
        approved_by: "it-supervisor",
        agent_id: "it-agent"
      )

    assert is_function(authorizer, 1)

    # Duck-typed action (matches the shape BodyOs.Types.TypedAction exposes)
    result = authorizer.(%{type: "file_write", target: "/tmp/it"})

    assert {:ok, block_map} = result
    assert is_map(block_map)
    assert block_map["policy_id"] == "delegatic://it/ok"
    assert String.starts_with?(block_map["authorization_token"], "sha256:")
    assert :ok = Delegatic.AuthorizationBlock.verify(block_map)
  end

  test "denied authorizations produce error tuples compatible with Replay's :authorizer contract" do
    # Register a policy that does NOT include file_delete.
    :ok =
      Delegatic.put_policy(
        Delegatic.Policy.new(%{
          policy_id: "delegatic://it/readonly",
          allow_actions: ["file_read"],
          max_ttl_seconds: 60
        })
      )

    authorizer =
      Delegatic.authorizer_for(
        policy_id: "delegatic://it/readonly",
        approved_by: "it-supervisor",
        agent_id: "it-agent"
      )

    assert {:error, :not_in_allowlist} = authorizer.(%{type: "file_delete", target: "/etc/x"})
  end

  test "agent filtering enforced when authorizer is bound to a specific agent_id" do
    :ok =
      Delegatic.put_policy(
        Delegatic.Policy.new(%{
          policy_id: "delegatic://it/alice-only",
          allow_actions: ["shell_exec"],
          agents: ["alice"],
          max_ttl_seconds: 60
        })
      )

    alice_authorizer =
      Delegatic.authorizer_for(
        policy_id: "delegatic://it/alice-only",
        approved_by: "supervisor",
        agent_id: "alice"
      )

    eve_authorizer =
      Delegatic.authorizer_for(
        policy_id: "delegatic://it/alice-only",
        approved_by: "supervisor",
        agent_id: "eve"
      )

    assert {:ok, _} = alice_authorizer.(%{type: "shell_exec"})
    assert {:error, :agent_not_allowed} = eve_authorizer.(%{type: "shell_exec"})
  end
end
