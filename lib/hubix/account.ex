defmodule HubiX.Account do
  @moduledoc """
    This module is responsible for wrapping HTTP requests sent to hubIC.
  """

  require Logger


  @log_prefix "HubiX.Account"
  @base_url "https://api.hubic.com"
  @credentials_path "/1.0/account/credentials"
  @timeout 5000
  @request_headers [
    {"Content-Type", "application/x-www-form-urlencoded"},
    {"Connection", "Close"},
    {"Cache-Control", "no-cache, must-revalidate"},
    {"User-Agent", "RadioKit Vault"}
  ]
  @request_options [timeout: @timeout, recv_timeout: @timeout, follow_redirect: false]


  def get_credentials(access_token) do
    Logger.info "[#{@log_prefix} #{inspect(self())}] Fetching account credentials"
    case HTTPoison.request(:get, @base_url <> @credentials_path, "", build_headers(access_token), @request_options) do
      {:ok, %HTTPoison.Response{status_code: status_code, headers: headers, body: body}} ->
        case status_code do
          200 ->
            Logger.info "[#{@log_prefix} #{inspect(self())}] Successfully fetched account credentials"

            case Poison.Parser.parse(body) do
              {:ok, data} ->
                case data do
                  %{"token" => token, "expires" => expires, "endpoint" => endpoint} ->
                    {:ok, token, expires, endpoint}

                  _ ->
                    Logger.warn "[#{@log_prefix} #{inspect(self())}] Unable to find all necessary fields in the JSON"
                    {:error, {:json_params}}
                end
            end
            
          _ ->
            Logger.warn "[#{@log_prefix} #{inspect(self())}] Unexpected HTTP code while fetching account credentials, status_code = #{inspect(status_code)}, headers = #{inspect(headers)}"
            {:error, {:httpcode, status_code}}
        end

      {:error, reason} ->
        Logger.warn "[#{@log_prefix} #{inspect(self())}] HTTP error while fetching account credentials, reason = #{inspect(reason)}"
        {:error, {:httperror, reason}}
    end
  end


  defp build_headers(access_token) do
    @request_headers ++ [{"Authorization", "Bearer " <> access_token}]
  end
end
