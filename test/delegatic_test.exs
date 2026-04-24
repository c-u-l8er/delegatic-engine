defmodule DelegaticTest do
  @moduledoc """
  End-to-end behaviour tests for the Delegatic authorization kernel.

  Covers: Policy semantics (deny-by-default, allow/deny order,
  agent filtering), AuthorizationBlock signing + verification, TTL
  capping, and the `authorizer_for/1` helper that slots directly
  into OS-011 Replay flows.
  """
  use ExUnit.Case, async: false

  alias Delegatic.{AuthorizationBlock, Policy, PolicyStore}

  setup do
    Application.ensure_all_started(:delegatic)
    PolicyStore.clear()
    :ok
  end

  defp register_simple_policy(overrides \\ %{}) do
    policy_attrs =
      Map.merge(
        %{
          policy_id: "delegatic://test/simple",
          allow_actions: ["file_write", "shell_exec"],
          max_ttl_seconds: 600
        },
        overrides
      )

    policy = Policy.new(policy_attrs)
    :ok = Delegatic.put_policy(policy)
    policy
  end

  # ---- Policy.check/3 --------------------------------------------

  describe "Policy.check/3" do
    test "allows actions in the allowlist" do
      policy = Policy.new(%{policy_id: "p1", allow_actions: ["file_read"]})
      assert :ok = Policy.check(policy, "file_read", "anon")
    end

    test "deny-by-default when action is not in allowlist" do
      policy = Policy.new(%{policy_id: "p1", allow_actions: ["file_read"]})
      assert {:error, :not_in_allowlist} = Policy.check(policy, "file_delete", "anon")
    end

    test "deny_actions beats allow_actions" do
      policy =
        Policy.new(%{
          policy_id: "p1",
          allow_actions: ["file_delete"],
          deny_actions: ["file_delete"]
        })

      assert {:error, :denied_by_policy} = Policy.check(policy, "file_delete", "anon")
    end

    test "agents nil means any agent allowed" do
      policy = Policy.new(%{policy_id: "p1", allow_actions: ["x"], agents: nil})
      assert :ok = Policy.check(policy, "x", "anyone")
      assert :ok = Policy.check(policy, "x", "someone-else")
    end

    test "agents list restricts to named agents" do
      policy =
        Policy.new(%{policy_id: "p1", allow_actions: ["x"], agents: ["alice", "bob"]})

      assert :ok = Policy.check(policy, "x", "alice")
      assert :ok = Policy.check(policy, "x", "bob")
      assert {:error, :agent_not_allowed} = Policy.check(policy, "x", "eve")
    end
  end

  # ---- PolicyStore ----------------------------------------------

  describe "PolicyStore" do
    test "put + get round-trip" do
      policy = register_simple_policy()

      assert {:ok, fetched} = PolicyStore.get("delegatic://test/simple")
      assert fetched.policy_id == policy.policy_id
    end

    test "get returns not_found for unknown id" do
      assert {:error, :not_found} = PolicyStore.get("nope")
    end

    test "delete removes a policy" do
      register_simple_policy()
      :ok = PolicyStore.delete("delegatic://test/simple")
      assert {:error, :not_found} = PolicyStore.get("delegatic://test/simple")
    end

    test "list returns every registered policy" do
      register_simple_policy()
      register_simple_policy(%{policy_id: "delegatic://test/other"})

      ids = PolicyStore.list() |> Enum.map(& &1.policy_id) |> Enum.sort()
      assert ids == ["delegatic://test/other", "delegatic://test/simple"]
    end
  end

  # ---- AuthorizationBlock ---------------------------------------

  describe "AuthorizationBlock" do
    test "new/3 produces a signed block with ISO8601 timestamps" do
      block = AuthorizationBlock.new("delegatic://p", "approver@x", 300)

      assert block.policy_id == "delegatic://p"
      assert block.approved_by == "approver@x"
      assert %DateTime{} = block.approved_at
      assert %DateTime{} = block.expires_at
      assert DateTime.compare(block.expires_at, block.approved_at) == :gt
      assert block.authorization_token =~ ~r/^sha256:[0-9a-f]{64}$/
    end

    test "verify/1 accepts a well-formed unexpired block" do
      block = AuthorizationBlock.new("p", "a", 300)
      assert :ok = AuthorizationBlock.verify(block)
    end

    test "verify/1 rejects a block whose token was mutated" do
      block = AuthorizationBlock.new("p", "a", 300)
      tampered = %{block | authorization_token: "sha256:00"}
      assert {:error, :token_mismatch} = AuthorizationBlock.verify(tampered)
    end

    test "verify/1 rejects an expired block" do
      block = AuthorizationBlock.new("p", "a", 1)
      :timer.sleep(1100)
      assert {:error, :expired} = AuthorizationBlock.verify(block)
    end

    test "to_map/1 + from_map/1 round-trip preserves identity" do
      block = AuthorizationBlock.new("p", "a", 300)
      map = AuthorizationBlock.to_map(block)
      assert {:ok, rebuilt} = AuthorizationBlock.from_map(map)

      assert rebuilt.policy_id == block.policy_id
      assert rebuilt.approved_by == block.approved_by
      assert rebuilt.authorization_token == block.authorization_token
      assert :ok = AuthorizationBlock.verify(rebuilt)
    end

    test "verify/1 works on a plain map (convenience)" do
      block = AuthorizationBlock.new("p", "a", 300)
      map = AuthorizationBlock.to_map(block)
      assert :ok = AuthorizationBlock.verify(map)
    end
  end

  # ---- Delegatic.authorize/1 ------------------------------------

  describe "Delegatic.authorize/1" do
    test "success path: registered policy + allowed action + allowed agent → {:ok, block}" do
      register_simple_policy()

      assert {:ok, block} =
               Delegatic.authorize(
                 action_type: "file_write",
                 policy_id: "delegatic://test/simple",
                 agent_id: "ops-agent",
                 approved_by: "supervisor@acme"
               )

      assert block.policy_id == "delegatic://test/simple"
      assert :ok = AuthorizationBlock.verify(block)
    end

    test "missing required fields returns :missing_required_field" do
      assert {:error, :missing_required_field} =
               Delegatic.authorize(action_type: "x", policy_id: "y")
    end

    test "unknown policy returns :not_found" do
      assert {:error, :not_found} =
               Delegatic.authorize(
                 action_type: "x",
                 policy_id: "missing",
                 agent_id: "a",
                 approved_by: "b"
               )
    end

    test "action not in allowlist returns :not_in_allowlist" do
      register_simple_policy()

      assert {:error, :not_in_allowlist} =
               Delegatic.authorize(
                 action_type: "process_spawn",
                 policy_id: "delegatic://test/simple",
                 agent_id: "a",
                 approved_by: "b"
               )
    end

    test "action in deny_actions returns :denied_by_policy" do
      register_simple_policy(%{deny_actions: ["shell_exec"], allow_actions: ["shell_exec"]})

      assert {:error, :denied_by_policy} =
               Delegatic.authorize(
                 action_type: "shell_exec",
                 policy_id: "delegatic://test/simple",
                 agent_id: "a",
                 approved_by: "b"
               )
    end

    test "agent not in allowlist returns :agent_not_allowed" do
      register_simple_policy(%{agents: ["alice"]})

      assert {:error, :agent_not_allowed} =
               Delegatic.authorize(
                 action_type: "file_write",
                 policy_id: "delegatic://test/simple",
                 agent_id: "eve",
                 approved_by: "b"
               )
    end

    test "requested ttl is capped at policy.max_ttl_seconds" do
      register_simple_policy(%{max_ttl_seconds: 60})

      {:ok, block} =
        Delegatic.authorize(
          action_type: "file_write",
          policy_id: "delegatic://test/simple",
          agent_id: "a",
          approved_by: "b",
          ttl_seconds: 3600
        )

      actual_ttl = DateTime.diff(block.expires_at, block.approved_at)
      assert actual_ttl <= 60
    end
  end

  # ---- authorizer_for/1 integration-shape ------------------------

  describe "authorizer_for/1" do
    test "returns a function matching the Replay :authorizer signature" do
      register_simple_policy()

      fun =
        Delegatic.authorizer_for(
          policy_id: "delegatic://test/simple",
          approved_by: "supervisor@acme",
          agent_id: "ops-agent"
        )

      # Simulate the TypedAction struct shape (any struct with :type works)
      fake_action = %{type: "file_write", target: "/tmp/x"}

      assert {:ok, block_map} = fun.(fake_action)
      assert is_map(block_map)
      assert block_map["policy_id"] == "delegatic://test/simple"
      assert :ok = AuthorizationBlock.verify(block_map)
    end

    test "returns {:error, reason} for denied actions" do
      register_simple_policy(%{allow_actions: ["file_read"]})

      fun =
        Delegatic.authorizer_for(
          policy_id: "delegatic://test/simple",
          approved_by: "supervisor@acme",
          agent_id: "ops-agent"
        )

      fake_action = %{type: "file_delete", target: "/tmp/x"}

      assert {:error, :not_in_allowlist} = fun.(fake_action)
    end

    test "agent_id flows through to the policy check" do
      register_simple_policy(%{agents: ["alice"]})

      fun =
        Delegatic.authorizer_for(
          policy_id: "delegatic://test/simple",
          approved_by: "supervisor@acme",
          agent_id: "eve"
        )

      fake_action = %{type: "file_write", target: "/tmp/x"}
      assert {:error, :agent_not_allowed} = fun.(fake_action)
    end
  end
end
