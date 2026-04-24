defmodule Delegatic.HttpRouter do
  @moduledoc """
  HTTP transport for the Delegatic MCP server. Mounts the Anubis
  Streamable HTTP plug at `/mcp` and exposes a small health endpoint.
  Used when `DELEGATIC_TRANSPORT=http`.
  """

  use Plug.Router

  plug(Plug.Logger, log: :debug)
  plug(:add_cors_headers)
  plug(:match)
  plug(:dispatch)

  get "/health" do
    payload = %{
      status: "ok",
      service: "delegatic",
      version: "0.1.0",
      policies_registered: length(Delegatic.PolicyStore.list())
    }

    conn
    |> put_resp_content_type("application/json")
    |> send_resp(200, Jason.encode!(payload))
  end

  match "/mcp" do
    # Runtime resolution to avoid compile-time dep on the conditionally
    # compiled Anubis StreamableHTTP plug (same pattern as body-*.)
    mcp_plug = Module.concat([Anubis, Server, Transport, StreamableHTTP, Plug])
    opts = apply(mcp_plug, :init, [[server: Delegatic.MCP.Server]])
    apply(mcp_plug, :call, [conn, opts])
  end

  match _ do
    send_resp(conn, 404, "not found")
  end

  defp add_cors_headers(conn, _opts) do
    conn
    |> Plug.Conn.put_resp_header("access-control-allow-origin", "*")
    |> Plug.Conn.put_resp_header("access-control-allow-methods", "GET,POST,OPTIONS")
    |> Plug.Conn.put_resp_header(
      "access-control-allow-headers",
      "content-type, mcp-session-id"
    )
  end
end
