defmodule Delegatic.PolicyStore do
  @moduledoc """
  In-memory policy store backed by an ETS table. Policies are keyed by
  their `policy_id` string — the same string referenced in GRASP
  `AuthorizationBlock.policy_id`.

  A production deployment would swap this for a Postgres-backed store
  via `Application.put_env(:delegatic, :policy_store, MyApp.PgStore)`
  and a behaviour-based adapter; v0.1 ships the ETS impl only.
  """

  use GenServer

  alias Delegatic.Policy

  @table :delegatic_policies

  # -- lifecycle --

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    ensure_table()
    {:ok, %{}}
  end

  # -- public API --

  @doc "Insert or replace a policy."
  @spec put(Policy.t()) :: :ok
  def put(%Policy{} = policy) do
    ensure_table()
    :ets.insert(@table, {policy.policy_id, policy})
    :ok
  end

  @doc "Look up a policy by id."
  @spec get(String.t()) :: {:ok, Policy.t()} | {:error, :not_found}
  def get(policy_id) when is_binary(policy_id) do
    ensure_table()

    case :ets.lookup(@table, policy_id) do
      [{^policy_id, policy}] -> {:ok, policy}
      _ -> {:error, :not_found}
    end
  end

  @doc "Remove a policy by id."
  @spec delete(String.t()) :: :ok
  def delete(policy_id) when is_binary(policy_id) do
    ensure_table()
    :ets.delete(@table, policy_id)
    :ok
  end

  @doc "Clear every policy — useful for test setup."
  @spec clear() :: :ok
  def clear do
    ensure_table()
    :ets.delete_all_objects(@table)
    :ok
  end

  @doc "List all policies currently in the store."
  @spec list() :: [Policy.t()]
  def list do
    ensure_table()

    @table
    |> :ets.tab2list()
    |> Enum.map(fn {_id, policy} -> policy end)
  end

  # -- internal --

  defp ensure_table do
    case :ets.whereis(@table) do
      :undefined ->
        :ets.new(@table, [:set, :named_table, :public, read_concurrency: true])

      _ ->
        :ok
    end
  end
end
