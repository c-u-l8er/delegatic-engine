defmodule Delegatic.MixProject do
  use Mix.Project

  @version "0.1.0"

  def project do
    [
      app: :delegatic,
      version: @version,
      elixir: "~> 1.17",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      name: "delegatic",
      description:
        "OS-006 Governance Shim — authorization kernel for the [&] Protocol ecosystem. " <>
          "Issues fresh AuthorizationBlocks to destructive edges in OS-011 &body.* replay flows. " <>
          "Policy-based deny-by-default; pluggable policy store.",
      source_url: "https://github.com/c-u-l8er/delegatic"
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto],
      mod: {Delegatic.Application, []}
    ]
  end

  defp deps do
    [
      # MCP server — hex-published `anubis_mcp` v0.17.x (same version the
      # graphonomous vendor snapshot is built from; no local patches).
      {:anubis_mcp, "~> 0.17.0"},
      # HTTP transport for Fly.io deploy
      {:plug, "~> 1.18"},
      {:bandit, "~> 1.6"},
      {:jason, "~> 1.4"}
    ]
  end
end
