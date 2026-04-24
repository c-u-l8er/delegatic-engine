defmodule Delegatic.MCP.Server do
  @moduledoc """
  Anubis-based MCP server exposing the Delegatic authorization
  kernel over JSON-RPC.

  Tool surface:

    * `delegatic_put_policy`     — register/replace a Policy
    * `delegatic_get_policy`     — look up a Policy by id
    * `delegatic_list_policies`  — list every registered Policy
    * `delegatic_delete_policy`  — remove a Policy by id
    * `delegatic_authorize`      — issue a fresh AuthorizationBlock
    * `delegatic_verify`         — verify an AuthorizationBlock's signature+TTL

  Consumers (body-browser-mcp, body-os-mcp, FleetPrompt InstallEngine,
  Graphonomous replay flows) can call `delegatic_authorize` over MCP
  to obtain the fresh block they need to pass into each destructive
  edge per OS-011 §4.4.
  """

  use Anubis.Server,
    name: "delegatic",
    version: "0.1.0",
    capabilities: [:tools]

  component(Delegatic.MCP.PutPolicy)
  component(Delegatic.MCP.GetPolicy)
  component(Delegatic.MCP.ListPolicies)
  component(Delegatic.MCP.DeletePolicy)
  component(Delegatic.MCP.Authorize)
  component(Delegatic.MCP.Verify)
end
