defmodule HubiX.Mixfile do
  use Mix.Project

  def project do
    [app: :hubix,
     version: "0.1.0",
     elixir: "~> 1.1",
     elixirc_paths: elixirc_paths(Mix.env),
     description: "hubiC client",
     name: "hubiX",
     source_url: "https://github.com/mspanc/hubix",
     package: package,
     preferred_cli_env: [espec: :test],
     deps: deps]
  end


  def application do
    [applications: [:crypto, :httpoison, :openstax_swift],
     mod: {HubiX, []}]
  end


  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_),     do: ["lib",]


  defp deps do
    deps(:test_dev)
  end


  defp deps(:test_dev) do
    [
      {:httpoison, "~> 0.8.2"},
      {:poison, "~> 1.2"},
      {:openstax_swift, github: "mspanc/openstax_swift"},
      {:espec, "~> 0.8.17", only: :test}
    ]
  end


  defp package do
    [description: "hubiC client",
     files: ["lib",  "mix.exs", "README*"],
     maintainers: ["Marcin Lewandowski"],
     licenses: ["MIT"],
     links: %{github: "https://github.com/mspanc/hubix"}]
  end
end
