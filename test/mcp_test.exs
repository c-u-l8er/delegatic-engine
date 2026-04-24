defmodule Delegatic.MCPTest do
  @moduledoc """
  Unit tests for the Delegatic MCP tool surface — every tool is a plain
  module with `execute/2` so we drive it directly without standing up
  an Anubis server.
  """
  use ExUnit.Case, async: false

  alias Delegatic.{AuthorizationBlock, Policy, PolicyStore}

  alias Delegatic.MCP.{
    Authorize,
    DeletePolicy,
    GetPolicy,
    ListPolicies,
    PutPolicy,
    Verify
  }

  setup do
    Application.ensure_all_started(:delegatic)
    PolicyStore.clear()
    :ok
  end

  # ---- PutPolicy -------------------------------------------------

  describe "PutPolicy" do
    test "registers a policy from a JSON object via the `policy` field" do
      policy_json =
        Jason.encode!(%{
          "policy_id" => "delegatic://mcp/test",
          "allow_actions" => ["file_write"],
          "max_ttl_seconds" => 120
        })

      assert {:reply, response, _} = PutPolicy.execute(%{policy: policy_json}, %{})
      assert response.structured_content.status == "ok"
      assert response.structured_content.policy.policy_id == "delegatic://mcp/test"
      assert response.structured_content.policy.allow_actions == ["file_write"]

      assert {:ok, %Policy{}} = PolicyStore.get("delegatic://mcp/test")
    end

    test "registers a policy from top-level fields when `policy` is absent" do
      assert {:reply, response, _} =
               PutPolicy.execute(
                 %{
                   policy_id: "delegatic://mcp/top-level",
                   allow_actions: Jason.encode!(["shell_exec"]),
                   max_ttl_seconds: 30
                 },
                 %{}
               )

      assert response.structured_content.status == "ok"
      assert {:ok, policy} = PolicyStore.get("delegatic://mcp/top-level")
      assert policy.allow_actions == ["shell_exec"]
    end

    test "rejects when policy_id is missing" do
      assert {:reply, response, _} =
               PutPolicy.execute(%{policy: Jason.encode!(%{"allow_actions" => ["x"]})}, %{})

      assert response.isError == true
      assert response.structured_content.error == "missing_policy_id"
    end

    test "rejects malformed policy JSON" do
      assert {:reply, response, _} = PutPolicy.execute(%{policy: "not-json"}, %{})
      assert response.isError == true
      assert response.structured_content.error == "invalid_policy"
    end
  end

  # ---- GetPolicy / ListPolicies / DeletePolicy -------------------

  describe "GetPolicy / ListPolicies / DeletePolicy" do
    setup do
      Delegatic.put_policy(
        Policy.new(%{policy_id: "a", allow_actions: ["x"], max_ttl_seconds: 10})
      )

      Delegatic.put_policy(
        Policy.new(%{policy_id: "b", allow_actions: ["y"], max_ttl_seconds: 10})
      )

      :ok
    end

    test "GetPolicy returns the registered policy" do
      assert {:reply, response, _} = GetPolicy.execute(%{policy_id: "a"}, %{})
      assert response.structured_content.status == "ok"
      assert response.structured_content.policy.policy_id == "a"
    end

    test "GetPolicy returns not_found error for unknown id" do
      assert {:reply, response, _} = GetPolicy.execute(%{policy_id: "nope"}, %{})
      assert response.isError == true
      assert response.structured_content.error == "not_found"
    end

    test "ListPolicies returns all registered policies" do
      assert {:reply, response, _} = ListPolicies.execute(%{}, %{})
      assert response.structured_content.status == "ok"
      assert response.structured_content.count == 2

      ids =
        response.structured_content.policies
        |> Enum.map(& &1.policy_id)
        |> Enum.sort()

      assert ids == ["a", "b"]
    end

    test "DeletePolicy removes the policy" do
      assert {:reply, response, _} = DeletePolicy.execute(%{policy_id: "a"}, %{})
      assert response.structured_content.status == "ok"
      assert response.structured_content.deleted == "a"

      assert {:error, :not_found} = PolicyStore.get("a")
    end
  end

  # ---- Authorize -------------------------------------------------

  describe "Authorize" do
    setup do
      Delegatic.put_policy(
        Policy.new(%{
          policy_id: "delegatic://mcp/ops",
          allow_actions: ["file_write", "shell_exec"],
          max_ttl_seconds: 300
        })
      )

      :ok
    end

    test "issues a signed AuthorizationBlock on success" do
      assert {:reply, response, _} =
               Authorize.execute(
                 %{
                   action_type: "file_write",
                   policy_id: "delegatic://mcp/ops",
                   agent_id: "ops-agent",
                   approved_by: "supervisor@acme"
                 },
                 %{}
               )

      assert response.structured_content.status == "ok"
      block = response.structured_content.authorization_block
      assert block["policy_id"] == "delegatic://mcp/ops"
      assert String.starts_with?(block["authorization_token"], "sha256:")
      assert :ok = AuthorizationBlock.verify(block)
    end

    test "denies actions outside the allowlist" do
      assert {:reply, response, _} =
               Authorize.execute(
                 %{
                   action_type: "file_delete",
                   policy_id: "delegatic://mcp/ops",
                   agent_id: "ops-agent",
                   approved_by: "supervisor@acme"
                 },
                 %{}
               )

      assert response.isError == true
      assert response.structured_content.error == "not_in_allowlist"
    end

    test "returns not_found for unknown policy" do
      assert {:reply, response, _} =
               Authorize.execute(
                 %{
                   action_type: "x",
                   policy_id: "missing",
                   agent_id: "a",
                   approved_by: "b"
                 },
                 %{}
               )

      assert response.isError == true
      assert response.structured_content.error == "not_found"
    end
  end

  # ---- Verify ----------------------------------------------------

  describe "Verify" do
    setup do
      Delegatic.put_policy(Policy.new(%{policy_id: "v", allow_actions: ["x"]}))
      :ok
    end

    test "verifies a well-formed block" do
      {:ok, block} =
        Delegatic.authorize(
          action_type: "x",
          policy_id: "v",
          agent_id: "a",
          approved_by: "b"
        )

      block_json = Jason.encode!(AuthorizationBlock.to_map(block))

      assert {:reply, response, _} =
               Verify.execute(%{authorization_block: block_json}, %{})

      assert response.structured_content.status == "ok"
      assert response.structured_content.verified == true
    end

    test "reports `verified: false` for tampered blocks" do
      {:ok, block} =
        Delegatic.authorize(
          action_type: "x",
          policy_id: "v",
          agent_id: "a",
          approved_by: "b"
        )

      tampered =
        block
        |> AuthorizationBlock.to_map()
        |> Map.put("authorization_token", "sha256:00")
        |> Jason.encode!()

      assert {:reply, response, _} =
               Verify.execute(%{authorization_block: tampered}, %{})

      assert response.structured_content.status == "ok"
      assert response.structured_content.verified == false
      assert response.structured_content.reason == "token_mismatch"
    end

    test "rejects malformed authorization_block JSON" do
      assert {:reply, response, _} =
               Verify.execute(%{authorization_block: "not-json"}, %{})

      assert response.isError == true
      assert response.structured_content.error == "invalid_block"
    end
  end
end
