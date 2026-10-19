defmodule Delegatic.AuthorizationBlock do
  @moduledoc """
  The GRASP §4.4 AuthorizationBlock — a transient proof-of-authorization
  issued by Delegatic to cover exactly one destructive-edge execution.

  Contract (strict):

      %{
        "policy_id"            => String,  # delegatic://... URI
        "approved_by"          => String,  # actor id / role
        "approved_at"          => String,  # ISO8601 UTC
        "expires_at"           => String,  # ISO8601 UTC
        "authorization_token"  => String   # sha256:<hex> HMAC over the rest
      }

  The token is NOT a secret — it is a tamper-evident HMAC so replay
  consumers can detect forged or mutated blocks. The HMAC key lives
  in `:delegatic, :hmac_key` application env; if unset, a per-process
  random key is used (fine for tests; unsafe for prod).
  """

  alias __MODULE__

  @type t :: %AuthorizationBlock{
          policy_id: String.t(),
          approved_by: String.t(),
          approved_at: DateTime.t(),
          expires_at: DateTime.t(),
          authorization_token: String.t()
        }

  defstruct policy_id: nil,
            approved_by: nil,
            approved_at: nil,
            expires_at: nil,
            authorization_token: nil

  @doc """
  Build a new signed AuthorizationBlock.

    * `policy_id` — e.g. `"delegatic://workspace_42/deploy"`
    * `approved_by` — role or user id
    * `ttl_seconds` — how long the block remains valid
  """
  @spec new(String.t(), String.t(), pos_integer()) :: t()
  def new(policy_id, approved_by, ttl_seconds) when ttl_seconds > 0 do
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    expires_at = DateTime.add(now, ttl_seconds, :second)

    block = %AuthorizationBlock{
      policy_id: policy_id,
      approved_by: approved_by,
      approved_at: now,
      expires_at: expires_at
    }

    %AuthorizationBlock{block | authorization_token: sign(block)}
  end

  @doc """
  Serialize a block to the canonical GRASP JSON-ready map shape.
  """
  @spec to_map(t()) :: map()
  def to_map(%AuthorizationBlock{} = b) do
    %{
      "policy_id" => b.policy_id,
      "approved_by" => b.approved_by,
      "approved_at" => DateTime.to_iso8601(b.approved_at),
      "expires_at" => DateTime.to_iso8601(b.expires_at),
      "authorization_token" => b.authorization_token
    }
  end

  @doc """
  Verify a block: must be unexpired AND the token must match an HMAC
  recomputed over its other fields. Returns `:ok` or `{:error, reason}`.
  """
  @spec verify(t() | map()) :: :ok | {:error, atom()}
  def verify(%AuthorizationBlock{} = b) do
    now = DateTime.utc_now()

    cond do
      DateTime.compare(now, b.expires_at) == :gt ->
        {:error, :expired}

      sign(%AuthorizationBlock{b | authorization_token: nil}) != b.authorization_token ->
        {:error, :token_mismatch}

      true ->
        :ok
    end
  end

  def verify(map) when is_map(map) do
    with {:ok, b} <- from_map(map) do
      verify(b)
    end
  end

  @doc "Parse a plain map back into an AuthorizationBlock struct."
  @spec from_map(map()) :: {:ok, t()} | {:error, atom()}
  def from_map(map) when is_map(map) do
    with {:ok, approved_at} <- parse_iso8601(Map.get(map, "approved_at")),
         {:ok, expires_at} <- parse_iso8601(Map.get(map, "expires_at")) do
      {:ok,
       %AuthorizationBlock{
         policy_id: Map.get(map, "policy_id"),
         approved_by: Map.get(map, "approved_by"),
         approved_at: approved_at,
         expires_at: expires_at,
         authorization_token: Map.get(map, "authorization_token")
       }}
    end
  end

  # -- internal --

  defp sign(%AuthorizationBlock{} = b) do
    key = hmac_key()

    payload =
      "#{b.policy_id}|#{b.approved_by}|#{DateTime.to_iso8601(b.approved_at)}|#{DateTime.to_iso8601(b.expires_at)}"

    "sha256:" <> (:crypto.mac(:hmac, :sha256, key, payload) |> Base.encode16(case: :lower))
  end

  defp hmac_key do
    Application.get_env(:delegatic, :hmac_key) || per_node_fallback_key()
  end

  defp per_node_fallback_key do
    # Stable per-process pseudo-key (unsafe for prod; fine for tests
    # because both `new/3` and `verify/1` use the same key within the
    # same node).
    case :persistent_term.get({__MODULE__, :fallback_key}, nil) do
      nil ->
        key = :crypto.strong_rand_bytes(32)
        :persistent_term.put({__MODULE__, :fallback_key}, key)
        key

      key ->
        key
    end
  end

  defp parse_iso8601(v) when is_binary(v) do
    case DateTime.from_iso8601(v) do
      {:ok, dt, _offset} -> {:ok, dt}
      _ -> {:error, :invalid_timestamp}
    end
  end

  defp parse_iso8601(_), do: {:error, :invalid_timestamp}
end
