defmodule Delegatic.Application do
  @moduledoc """
  OTP Application for Delegatic. Starts:

    * `Delegatic.PolicyStore` — in-memory ETS-backed authorization policies
    * HTTP MCP transport (optional, when `DELEGATIC_TRANSPORT=http`)
  """

  use Application

  @impl true
  def start(_type, _args) do
    children =
      [
        Delegatic.PolicyStore
      ]
      |> maybe_start_http()

    Supervisor.start_link(children, strategy: :one_for_one, name: Delegatic.Supervisor)
  end

  defp maybe_start_http(children) do
    if System.get_env("DELEGATIC_TRANSPORT") == "http" do
      port = System.get_env("DELEGATIC_PORT", "4400") |> String.to_integer()

      children ++
        [
          {Anubis.Server.Registry, []},
          %{
            id: :delegatic_mcp_http,
            start:
              {Anubis.Server.Supervisor, :start_link,
               [
                 Delegatic.MCP.Server,
                 [transport: {:streamable_http, start: true}, request_timeout: 120_000]
               ]}
          },
          {Bandit, plug: Delegatic.HttpRouter, port: port, scheme: :http}
        ]
    else
      children
    end
  end
end
