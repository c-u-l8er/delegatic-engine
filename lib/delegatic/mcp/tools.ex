defmodule Delegatic.MCP.Shared do
  @moduledoc false

  alias Anubis.Server.Response

  def p(params, key, default \\ nil) when is_map(params) and is_atom(key) do
    Map.get(params, key, Map.get(params, Atom.to_string(key), default))
  end

  def ok(payload, frame) do
    {:reply, Response.tool() |> Response.structured(payload), frame}
  end

  def error(frame, code, reason) do
    payload = %{status: "error", error: to_string(code), reason: to_string_safe(reason)}

    {:reply,
     Response.tool()
     |> Response.structured(payload)
     |> Map.put(:isError, true), frame}
  end

  defp to_string_safe(v) when is_binary(v), do: v
  defp to_string_safe(v) when is_atom(v), do: Atom.to_string(v)
  defp to_string_safe(v), do: inspect(v)

  def decode_json(nil), do: {:ok, nil}
  def decode_json(v) when is_map(v), do: {:ok, v}

  def decode_json(v) when is_binary(v) do
    case Jason.decode(v) do
      {:ok, d} -> {:ok, d}
      {:error, _} -> {:error, :invalid_json}
    end
  end

  def decode_json(_), do: {:error, :invalid_json}

  def policy_to_map(%Delegatic.Policy{} = policy) do
    %{
      policy_id: policy.policy_id,
      description: policy.description,
      allow_actions: policy.allow_actions,
      deny_actions: policy.deny_actions,
      agents: policy.agents,
      max_ttl_seconds: policy.max_ttl_seconds,
      require_approval_by: policy.require_approval_by
    }
  end
end

defmodule Delegatic.MCP.PutPolicy do
  @moduledoc """
  Register or replace a Delegatic Policy. Accepts either a nested
  `policy` JSON object or top-level fields directly.
  """

  use Anubis.Server.Component, type: :tool

  import Delegatic.MCP.Shared
  alias Delegatic.Policy

  schema do
    field(:policy, :string, description: "Policy attrs as a JSON object (preferred)")
    field(:policy_id, :string, description: "Policy id (if not providing :policy)")
    field(:description, :string, description: "Human-readable description")
    field(:allow_actions, :string, description: "JSON array of allowed action types")
    field(:deny_actions, :string, description: "JSON array of denied action types")
    field(:agents, :string, description: "JSON array of agent ids; omit for any agent")
    field(:max_ttl_seconds, :number)
  end

  @impl true
  def execute(params, frame) do
    case extract_policy_attrs(params) do
      {:ok, attrs} ->
        policy = Policy.new(attrs)

        cond do
          is_nil(policy.policy_id) or policy.policy_id == "" ->
            error(frame, "missing_policy_id", "policy_id is required")

          true ->
            :ok = Delegatic.put_policy(policy)
            ok(%{status: "ok", policy: policy_to_map(policy)}, frame)
        end

      {:error, reason} ->
        error(frame, "invalid_policy", reason)
    end
  end

  defp extract_policy_attrs(params) do
    case p(params, :policy) do
      raw when is_binary(raw) or is_map(raw) ->
        decode_json(raw)

      _ ->
        # Build from individual fields
        with {:ok, allow} <- decode_list(p(params, :allow_actions)),
             {:ok, deny} <- decode_list(p(params, :deny_actions)),
             {:ok, agents} <- decode_list(p(params, :agents), allow_nil: true) do
          {:ok,
           %{
             policy_id: p(params, :policy_id),
             description: p(params, :description),
             allow_actions: allow || [],
             deny_actions: deny || [],
             agents: agents,
             max_ttl_seconds: p(params, :max_ttl_seconds, 600)
           }}
        end
    end
  end

  defp decode_list(v, opts \\ [])
  defp decode_list(nil, opts), do: if(opts[:allow_nil], do: {:ok, nil}, else: {:ok, []})
  defp decode_list(list, _) when is_list(list), do: {:ok, list}

  defp decode_list(binary, _) when is_binary(binary) do
    case Jason.decode(binary) do
      {:ok, l} when is_list(l) -> {:ok, l}
      _ -> {:error, :invalid_list_json}
    end
  end

  defp decode_list(_, _), do: {:error, :invalid_list_json}
end

defmodule Delegatic.MCP.GetPolicy do
  @moduledoc "Look up a Policy by its policy_id."

  use Anubis.Server.Component, type: :tool

  import Delegatic.MCP.Shared

  schema do
    field(:policy_id, :string, required: true)
  end

  @impl true
  def execute(params, frame) do
    case p(params, :policy_id) do
      id when is_binary(id) and id != "" ->
        case Delegatic.get_policy(id) do
          {:ok, policy} -> ok(%{status: "ok", policy: policy_to_map(policy)}, frame)
          {:error, :not_found} -> error(frame, "not_found", "no policy with id=#{id}")
        end

      _ ->
        error(frame, "missing_policy_id", "policy_id is required")
    end
  end
end

defmodule Delegatic.MCP.ListPolicies do
  @moduledoc "List every registered Policy."

  use Anubis.Server.Component, type: :tool

  import Delegatic.MCP.Shared

  schema do
  end

  @impl true
  def execute(_params, frame) do
    policies = Delegatic.PolicyStore.list() |> Enum.map(&policy_to_map/1)
    ok(%{status: "ok", count: length(policies), policies: policies}, frame)
  end
end

defmodule Delegatic.MCP.DeletePolicy do
  @moduledoc "Remove a Policy from the store."

  use Anubis.Server.Component, type: :tool

  import Delegatic.MCP.Shared

  schema do
    field(:policy_id, :string, required: true)
  end

  @impl true
  def execute(params, frame) do
    case p(params, :policy_id) do
      id when is_binary(id) and id != "" ->
        :ok = Delegatic.delete_policy(id)
        ok(%{status: "ok", deleted: id}, frame)

      _ ->
        error(frame, "missing_policy_id", "policy_id is required")
    end
  end
end

defmodule Delegatic.MCP.Authorize do
  @moduledoc """
  Issue a fresh AuthorizationBlock for a single action. The returned
  block is ready to attach to a TypedAction's `authorization` field
  for destructive-edge execution.
  """

  use Anubis.Server.Component, type: :tool

  import Delegatic.MCP.Shared
  alias Delegatic.AuthorizationBlock

  schema do
    field(:action_type, :string, required: true)
    field(:policy_id, :string, required: true)
    field(:agent_id, :string, required: true)
    field(:approved_by, :string, required: true)
    field(:ttl_seconds, :number, description: "Optional TTL (capped at policy.max_ttl_seconds)")
  end

  @impl true
  def execute(params, frame) do
    opts =
      [
        action_type: p(params, :action_type),
        policy_id: p(params, :policy_id),
        agent_id: p(params, :agent_id),
        approved_by: p(params, :approved_by)
      ]
      |> maybe_put(:ttl_seconds, p(params, :ttl_seconds))

    case Delegatic.authorize(opts) do
      {:ok, block} ->
        ok(
          %{
            status: "ok",
            authorization_block: AuthorizationBlock.to_map(block)
          },
          frame
        )

      {:error, reason} ->
        error(frame, to_string(reason), "authorization refused")
    end
  end

  defp maybe_put(list, _k, nil), do: list
  defp maybe_put(list, k, v), do: Keyword.put(list, k, v)
end

defmodule Delegatic.MCP.Verify do
  @moduledoc """
  Verify an AuthorizationBlock's HMAC signature and expiration. Safe
  to call from untrusted code — returns a pure `ok/error` without
  mutating state.
  """

  use Anubis.Server.Component, type: :tool

  import Delegatic.MCP.Shared
  alias Delegatic.AuthorizationBlock

  schema do
    field(:authorization_block, :string,
      required: true,
      description: "AuthorizationBlock as JSON or decoded object"
    )
  end

  @impl true
  def execute(params, frame) do
    with {:ok, map} <- decode_json(p(params, :authorization_block)),
         true <- is_map(map) do
      case AuthorizationBlock.verify(map) do
        :ok -> ok(%{status: "ok", verified: true}, frame)
        {:error, reason} -> ok(%{status: "ok", verified: false, reason: to_string(reason)}, frame)
      end
    else
      {:error, :invalid_json} ->
        error(frame, "invalid_block", "authorization_block must be a JSON object")

      false ->
        error(frame, "invalid_block", "authorization_block must be a JSON object")
    end
  end
end
