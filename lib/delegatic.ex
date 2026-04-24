defmodule Delegatic do
  @moduledoc """
  OS-006 Governance Shim — public authorization surface.

  The typical flow:

      # 1. Register a policy
      Delegatic.put_policy(Delegatic.Policy.new(%{
        policy_id: "delegatic://ws-42/deploy",
        allow_actions: ["file_write", "shell_exec"],
        max_ttl_seconds: 300,
        agents: ["ops-agent"]
      }))

      # 2. Request authorization for one action
      {:ok, block} =
        Delegatic.authorize(
          action_type: "file_write",
          policy_id: "delegatic://ws-42/deploy",
          agent_id: "ops-agent",
          approved_by: "supervisor@acme"
        )

      # 3. Pass the block into the body provider
      body_os_act.(%{type: "file_write", ..., authorization: Delegatic.AuthorizationBlock.to_map(block)})

  The authorizer factory in `authorizer_for/1` returns a function
  matching the `(TypedAction.t() -> {:ok, map()} | {:error, term()})`
  shape expected by `BodyBrowser.Replay.execute/3` and
  `BodyOs.Replay.execute/3`. Wiring Delegatic into a replay flow is
  therefore a single function call.
  """

  alias Delegatic.{AuthorizationBlock, Policy, PolicyStore}

  @type authorize_opts :: [
          action_type: String.t(),
          policy_id: String.t(),
          agent_id: String.t(),
          approved_by: String.t(),
          ttl_seconds: pos_integer() | nil
        ]

  # -- policy management --

  @doc "Register (or replace) a policy in the store."
  @spec put_policy(Policy.t()) :: :ok
  def put_policy(%Policy{} = policy), do: PolicyStore.put(policy)

  @doc "Look up a policy by id."
  @spec get_policy(String.t()) :: {:ok, Policy.t()} | {:error, :not_found}
  def get_policy(id), do: PolicyStore.get(id)

  @doc "Remove a policy by id."
  @spec delete_policy(String.t()) :: :ok
  def delete_policy(id), do: PolicyStore.delete(id)

  # -- authorization --

  @doc """
  Authorize a single action. Consults the referenced policy, then on
  success issues a freshly-signed `AuthorizationBlock`.

  Returns `{:ok, block}` or `{:error, reason}`. Reasons:
    * `:policy_not_found`
    * `:denied_by_policy`
    * `:agent_not_allowed`
    * `:not_in_allowlist`
    * `:missing_required_field`
  """
  @spec authorize(authorize_opts()) :: {:ok, AuthorizationBlock.t()} | {:error, atom()}
  def authorize(opts) do
    with {:ok, required} <- extract_required(opts),
         {:ok, policy} <- get_policy(required.policy_id),
         :ok <- Policy.check(policy, required.action_type, required.agent_id) do
      ttl = capped_ttl(opts, policy)
      {:ok, AuthorizationBlock.new(required.policy_id, required.approved_by, ttl)}
    else
      {:error, _} = err -> err
    end
  end

  @doc """
  Convenience: build the `:authorizer` function Replay expects,
  pre-bound to a policy + approver.

  The returned function takes a `TypedAction.t()` struct (duck-typed —
  any struct with `:type` and optional `:target` works), consults the
  given policy, and returns `{:ok, block_map}` ready to attach to the
  action.
  """
  @spec authorizer_for(keyword()) :: (struct() -> {:ok, map()} | {:error, atom()})
  def authorizer_for(opts) do
    policy_id = Keyword.fetch!(opts, :policy_id)
    approved_by = Keyword.fetch!(opts, :approved_by)
    agent_id = Keyword.get(opts, :agent_id, "anonymous")
    ttl = Keyword.get(opts, :ttl_seconds)

    fn action ->
      auth_opts = [
        action_type: Map.get(action, :type),
        policy_id: policy_id,
        agent_id: agent_id,
        approved_by: approved_by
      ]

      auth_opts = if ttl, do: Keyword.put(auth_opts, :ttl_seconds, ttl), else: auth_opts

      case authorize(auth_opts) do
        {:ok, block} -> {:ok, AuthorizationBlock.to_map(block)}
        {:error, reason} -> {:error, reason}
      end
    end
  end

  # -- private --

  defp extract_required(opts) do
    required =
      %{
        action_type: Keyword.get(opts, :action_type),
        policy_id: Keyword.get(opts, :policy_id),
        agent_id: Keyword.get(opts, :agent_id),
        approved_by: Keyword.get(opts, :approved_by)
      }

    if Enum.any?(required, fn {_k, v} -> is_nil(v) or v == "" end) do
      {:error, :missing_required_field}
    else
      {:ok, required}
    end
  end

  defp capped_ttl(opts, policy) do
    requested = Keyword.get(opts, :ttl_seconds, policy.max_ttl_seconds)
    min(requested, policy.max_ttl_seconds)
  end
end
