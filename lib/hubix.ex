defmodule HubiX do
  use Application


  def version do
    "0.1.0"
  end


  def start(_type, _args) do
    import Supervisor.Spec, warn: false

    children = [
      worker(HubiX.AuthAgent, [[name: HubiX.AuthAgent]])
    ]

    opts = [strategy: :one_for_one, name: HubiX]
    Supervisor.start_link(children, opts)
  end
end
