defmodule Delegatic.Policy do
  @moduledoc """
  A `Policy` defines the authorization rules for a named `policy_id`.
  Policies live in the Delegatic PolicyStore and are referenced by
  the `policy_id` field of a GRASP AuthorizationBlock (e.g.
  `delegatic://workspace_42/deploy`).

  The minimal kernel supports:

    * **deny-by-default** — every action must be explicitly allowed
    * **allow_actions** — explicit allowlist of action types
    * **deny_actions** — denylist applied after allowlist (wins on conflict)
    * **agents** — optional allowlist of agent ids; `nil` means any agent
    * **max_ttl_seconds** — cap on issued authorization lifetime
    * **require_approval_by** — optional list of roles that must approve;
      the authorizer enforces by requiring the caller to assert one of them

  Full spec OS-006 §3.4 defines many more knobs (budget, tiers, etc.);
  those land as additive fields in future `0.x` versions without
  breaking the current v0.1 contract.
  """

  @type t :: %__MODULE__{
          policy_id: String.t(),
          description: String.t() | nil,
          allow_actions: [String.t()],
          deny_actions: [String.t()],
          agents: [String.t()] | nil,
          max_ttl_seconds: pos_integer(),
          require_approval_by: [String.t()]
        }

  defstruct policy_id: nil,
            description: nil,
            allow_actions: [],
            deny_actions: [],
            agents: nil,
            max_ttl_seconds: 600,
            require_approval_by: []

  @doc """
  Create a new Policy from attrs. Both string and atom keys accepted.
  """
  @spec new(map() | keyword()) :: t()
  def new(attrs) when is_list(attrs), do: new(Map.new(attrs))

  def new(attrs) when is_map(attrs) do
    %__MODULE__{
      policy_id: get(attrs, :policy_id),
      description: get(attrs, :description),
      allow_actions: get_list(attrs, :allow_actions),
      deny_actions: get_list(attrs, :deny_actions),
      agents: get_agents(attrs),
      max_ttl_seconds: get(attrs, :max_ttl_seconds, 600),
      require_approval_by: get_list(attrs, :require_approval_by)
    }
  end

  @doc """
  Check whether an action is permitted under the policy for the given
  agent. Returns `:ok` or `{:error, reason}`.

  Order of evaluation:
    1. action in `deny_actions` → `{:error, :denied_by_policy}`
    2. agent filter (if set) not matched → `{:error, :agent_not_allowed}`
    3. action not in `allow_actions` → `{:error, :not_in_allowlist}`
    4. otherwise → `:ok`
  """
  @spec check(t(), String.t(), String.t()) :: :ok | {:error, atom()}
  def check(%__MODULE__{} = policy, action_type, agent_id)
      when is_binary(action_type) and is_binary(agent_id) do
    cond do
      action_type in policy.deny_actions ->
        {:error, :denied_by_policy}

      not agent_allowed?(policy.agents, agent_id) ->
        {:error, :agent_not_allowed}

      action_type not in policy.allow_actions ->
        {:error, :not_in_allowlist}

      true ->
        :ok
    end
  end

  defp agent_allowed?(nil, _), do: true
  defp agent_allowed?(list, agent_id) when is_list(list), do: agent_id in list

  # -- helpers --

  defp get(map, key, default \\ nil) when is_atom(key) do
    Map.get(map, key, Map.get(map, Atom.to_string(key), default))
  end

  defp get_list(map, key) do
    case get(map, key) do
      v when is_list(v) -> v
      _ -> []
    end
  end

  defp get_agents(attrs) do
    case get(attrs, :agents) do
      v when is_list(v) -> v
      _ -> nil
    end
  end
end
