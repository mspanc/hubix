defmodule HubiX.OAuth2 do
  @moduledoc """
    This module is responsible for wrapping HTTP requests sent to hubIC.
  """

  require Logger


  @log_prefix "HubiX.OAuth2"
  @base_url "https://api.hubic.com"
  @request_token_base_url "/oauth/auth/"
  @exchange_code_base_url "/oauth/token/"
  @refresh_token_base_url "/oauth/token/"
  @timeout 30000
  @request_headers [
    {"Content-Type", "application/x-www-form-urlencoded"},
    {"Connection", "Close"},
    {"Cache-Control", "no-cache, must-revalidate"},
    {"User-Agent", "hubiX/#{HubiX.version}"}
  ]
  @request_options [timeout: @timeout, recv_timeout: @timeout, follow_redirect: false]
  @scope_string "credentials.r"
  @scope_params [{"credentials", "r"}]


  @doc """
  This function does the complete authentication flow against hubIC.

  Returns `{:ok, access_token, expires_in, refresh_token}` in case of success,
  `{:error, reason}` otherwise.
  """
  def authenticate(client_id, client_secret, redirect_url, username, password) do
    case request_token(client_id, redirect_url) do
      {:ok, action_url, action_params, oauth2_state_challenge} ->
        Logger.info "[#{@log_prefix} #{inspect(self())}] Authenticate: Requested token"

        case confirm_access(action_url, action_params, username, password) do
          {:ok, code, oauth2_state_response} ->
            if oauth2_state_response == oauth2_state_challenge do
              Logger.info "[#{@log_prefix} #{inspect(self())}] Authenticate: Got code"
              case exchange_code(client_id, client_secret, code, redirect_url) do
                {:ok, access_token, expires_in, refresh_token} ->
                  Logger.info "[#{@log_prefix} #{inspect(self())}] Authenticate: Got access token"
                  {:ok, access_token, expires_in, refresh_token}

                {:error, reason} ->
                  Logger.warn "[#{@log_prefix} #{inspect(self())}] Authenticate: Unable to exchange code"
                  {:error, reason}
              end

            else
              Logger.warn "[#{@log_prefix} #{inspect(self())}] Authenticate: Received invalid OAuth2 state"
              {:error, :oauth2_state_invalid}
            end

          {:error, reason} ->
            Logger.warn "[#{@log_prefix} #{inspect(self())}] Authenticate: Unable to get code"
            {:error, reason}
        end

      {:error, reason} ->
        Logger.warn "[#{@log_prefix} #{inspect(self())}] Authenticate: Unable to request token"
        {:error, reason}
    end
  end



  @doc """
  This functions starts the authentication phase.

  In practice it starts the OAuth2 Authorization Code flow. If everything goes
  well hubIC will render authentication view, querying for username/password.
  Function parses received HTML, extracts hidden fields and form target URL,
  and generates random OAuth2 state.

  In case of success it returns`{:ok, action_url, action_params, oauth2_state}`.
  The next request (see `confirm_access/4`) should point to `action_url`, contain
  `action_params` in the body along with username/password. OAuth2 state should
  be stored and and compared later on.

  In case of problems it returns `{:error, {:httpcode, status_code}}` (if
  unexpected code was returned from the server) or `{:error, {:httperror, reason}}`
  if transmission error occured.
  """
  def request_token(client_id, redirect_uri) do
    oauth2_state = Base.url_encode64(:crypto.strong_rand_bytes(48))
    params = [
      {"client_id", client_id},
      {"redirect_uri", redirect_uri},
      {"scope", @scope_string},
      {"state", oauth2_state},
      {"response_type", "code"}
    ]
    location = @base_url <> @request_token_base_url <> "?" <> serialize_params(params)

    Logger.info "[#{@log_prefix} #{inspect(self())}] Requesting token: GET #{location}"
    case HTTPoison.request(:get, location, "", @request_headers, @request_options) do
      {:ok, %HTTPoison.Response{status_code: status_code, body: body}} ->
        case status_code do
          200 ->
            tree = body |> Exquery.tree

            # We seek for <form> in the body and extract action attribute and extract its action attribute
            {{:tag, "form", form_attributes}, _} = tree |> Exquery.Query.one({:tag, "form", []})
            {"action", action_url} = List.keyfind(form_attributes, "action", 0)

            # We seek for <input name="oauth"> in the body and extract its value attribute
            {:tag, "input", oauth_attributes} = tree |> Exquery.Query.one({:tag, "input", [{"name", "oauth"}]})
            {"value", oauth_id} = List.keyfind(oauth_attributes, "value", 0)

            action_params = [{"oauth", oauth_id}]
            Logger.info "[#{@log_prefix} #{inspect(self())}] Got response 200, action URL = #{inspect(action_url)}, action params = #{inspect(action_params)}"
            {:ok, action_url, action_params, oauth2_state}

          _ ->
            {:error, {:httpcode, status_code}}
        end

      {:error, reason} ->
        {:error, {:httperror, reason}}
    end
  end


  @doc """
  This functions confirms that certain user has access to the hubIC app.
  Obviously the app must be owned by the user which credentials you are passing.

  In practice it retreives code defined in OAuth2 Authorization Code flow.

  If everything goes well hubIC will cause redirect with URL that contain certain
  attributes in the query string: used to receive actual access token and OAuth2
  state that should match state generated in previous call (see `request_token/3`).
  It extracts these attributes.

  In case of success it returns`{:ok, code, oauth2_state}`.

  In case of problems it returns `{:error, {:httpcode, status_code}}` (if
  unexpected code was returned from the server), `{:error, {:httperror, reason}}`
  if transmission error occured or `{:error, {:oauth2, reason}}` if there was
  an issue on OAuth2 layer.
  """
  def confirm_access(confirm_base_url, confirm_params, username, password) do
    location = @base_url <> confirm_base_url
    full_params = confirm_params ++ @scope_params ++ [{"login", username}, {"user_pwd", password}, {"action", "accepted"}]
    body = serialize_params(full_params)

    Logger.info "[#{@log_prefix} #{inspect(self())}] Confirming access: POST #{location}, params = #{inspect(full_params)}"

    case HTTPoison.request(:post, location, body, @request_headers, @request_options) do
      {:ok, %HTTPoison.Response{status_code: status_code, headers: headers}} ->
        case status_code do
          302 ->
            Logger.info "[#{@log_prefix} #{inspect(self())}] Got response 302, headers = #{inspect(headers)}"
            {"Location", response_redirect_url} = headers |> List.keyfind("Location", 0)
            %URI{query: response_query_string} = URI.parse(response_redirect_url)
            response_query_params = URI.query_decoder(response_query_string) |> Enum.map(&(&1))

            case response_query_params |> List.keyfind("error", 0) do
              {"error", error} ->
                Logger.warn "[#{@log_prefix} #{inspect(self())}] Got OAuth2 error"
                {:error, {:oauth2, error}}

              nil ->
                {"code", response_code} = response_query_params |> List.keyfind("code", 0)
                {"state", response_oauth2_state} = response_query_params |> List.keyfind("state", 0)

                {:ok, response_code, response_oauth2_state}
            end

          _ ->
            Logger.warn "[#{@log_prefix} #{inspect(self())}] Got response #{status_code}"
            {:error, {:httpcode, status_code}}
        end

      {:error, reason} ->
        {:error, {:httperror, reason}}
    end
  end


  @doc """
  This functions exchanges code retreived using `confirm_access/4` for actual
  access token.

  If everything goes well hubIC will return JSON with access token, refresh token
  and expiration time of the current access token. It is parsed and returned
  as `{:ok, access_token, expires_in, refresh_token}`.

  In case of problems it returns `{:error, {:httpcode, status_code}}` (if
  unexpected code was returned from the server), `{:error, {:httperror, reason}}`
  if transmission error occured, `{:error, {:json_parse, reason}}` if there was
  an issue when parsing JSON or `{:error, {:json_params}}` if JSON was valid
  but it does not contain expected keys.
  """
  def exchange_code(client_id, client_secret, code, redirect_uri) do
    location = @base_url <> @exchange_code_base_url
    params = [
      {"code", code},
      {"redirect_uri", redirect_uri},
      {"grant_type", "authorization_code"}
    ]
    body = serialize_params(params)

    full_headers = @request_headers ++ [{"Authorization", "Basic #{Base.encode64(client_id <> ":" <> client_secret)}"}]

    Logger.info "[#{@log_prefix} #{inspect(self())}] Exchanging code for access token: POST #{location}, headers = #{inspect(full_headers)}, body = #{inspect(body)}"

    case HTTPoison.request(:post, location, body, full_headers, @request_options) do
      {:ok, %HTTPoison.Response{status_code: status_code, body: body}} ->
        case status_code do
          200 ->
            Logger.info "[#{@log_prefix} #{inspect(self())}] Got response 200, body = #{inspect(body)}"

            case Poison.Parser.parse(body) do
              {:ok, data} ->
                case data do
                  %{"access_token" => access_token, "expires_in" => expires_in, "refresh_token" => refresh_token, "token_type" => "Bearer"} ->
                    {:ok, access_token, expires_in, refresh_token}

                  _ ->
                    Logger.warn "[#{@log_prefix} #{inspect(self())}] Unable to find all necessary fields in the JSON"
                    {:error, {:json_params}}
                end

              {:error, reason} ->
                Logger.warn "[#{@log_prefix} #{inspect(self())}] Unable to parse JSON, reason = #{inspect(reason)}"
                {:error, {:json_parse, reason}}
            end

          _ ->
            {:error, {:httpcode, status_code}}
        end

      {:error, reason} ->
        {:error, {:httperror, reason}}
    end
  end


  @doc """
  This functions refreshes access token.

  If everything goes well hubIC will return JSON with access token, refresh token
  and expiration time of the current access token. It is parsed and returned
  as `{:ok, access_token, expires_in}`.

  In case of problems it returns `{:error, {:httpcode, status_code}}` (if
  unexpected code was returned from the server), `{:error, {:httperror, reason}}`
  if transmission error occured, `{:error, {:json_parse, reason}}` if there was
  an issue when parsing JSON or `{:error, {:json_params}}` if JSON was valid
  but it does not contain expected keys.
  """
  def refresh_token(client_id, client_secret, refresh_token) do
    location = @base_url <> @refresh_token_base_url
    params = [
      {"refresh_token", refresh_token},
      {"grant_type", "refresh_token"}
    ]
    body = serialize_params(params)

    full_headers = @request_headers ++ [{"Authorization", "Basic #{Base.encode64(client_id <> ":" <> client_secret)}"}]

    Logger.info "[#{@log_prefix} #{inspect(self())}] Refreshing access token: POST #{location}, headers = #{inspect(full_headers)}, body = #{inspect(body)}"

    case HTTPoison.request(:post, location, body, full_headers, @request_options) do
      {:ok, %HTTPoison.Response{status_code: status_code, body: body}} ->
        case status_code do
          200 ->
            Logger.info "[#{@log_prefix} #{inspect(self())}] Got response 200, body = #{inspect(body)}"

            case Poison.Parser.parse(body) do
              {:ok, data} ->
                case data do
                  %{"access_token" => access_token, "expires_in" => expires_in, "token_type" => "Bearer"} ->
                    {:ok, access_token, expires_in}

                  _ ->
                    Logger.warn "[#{@log_prefix} #{inspect(self())}] Unable to find all necessary fields in the JSON"
                    {:error, {:json_params}}
                end

              {:error, reason} ->
                Logger.warn "[#{@log_prefix} #{inspect(self())}] Unable to parse JSON, reason = #{inspect(reason)}"
                {:error, {:json_parse, reason}}
            end

          _ ->
            {:error, {:httpcode, status_code}}
        end

      {:error, reason} ->
        {:error, {:httperror, reason}}
    end
  end


  defp serialize_params(params) do
    Enum.join(Enum.map(params, fn(x) -> {key, value} = x; URI.encode_www_form(key) <> "=" <> URI.encode_www_form(value) end), "&")
  end
end
