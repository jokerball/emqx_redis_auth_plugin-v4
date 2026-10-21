%%--------------------------------------------------------------------
%% EMQX 4.4 Redis authentication plugin.
%%
%% Mirrors the logic of the TR369 auth service `unmtr369auth`
%% POST /mqtt/verify endpoint:
%%
%%   1. clientid/username/password missing          -> deny
%%   2. username in `white_service_list`            -> allow
%%   3. username == unm_username (UNM2000):
%%      AES-128-CBC (no padding, zero IV) decrypt of the base64 password
%%      must equal unm_expected_password             -> allow / deny
%%   4. otherwise: redis GET `snindex:{mac}` must exist -> allow / deny
%%   5. clientid containing keepalived_tag: HGET `ap:{apId}` `status`
%%      - missing value or the offline value         -> allow
%%      - any other value (main channel online)      -> deny
%%
%% Registered on the `client.authenticate` hook with a high priority so it
%% is consulted before the built-in authenticators. The verdict is always
%% terminal ({stop, _}), which matches the EMQX 5 plugin behaviour.
%%--------------------------------------------------------------------

-module(emqx_plugin_redis_auth).

-include_lib("kernel/include/logger.hrl").

-define(APP, emqx_plugin_redis_auth).

%% Built-in auth plugins register with priority 0, so any positive value
%% puts this plugin in front of them (as long as `auth_order` is not set).
-define(HOOK_PRIORITY, 1000).

-define(DEFAULT_WHITE_LIST,
        [<<"unmtr369service">>, <<"unmtr369bulkdataservice">>, <<"unmtr369accessservice">>]).

-export([load/1, unload/0]).

%% `client.authenticate' hook callback
-export([authenticate/2]).

-export([get_config/0, ping/0, redis_options/0]).

%%--------------------------------------------------------------------
%% Plugin lifecycle
%%--------------------------------------------------------------------

load(_Env) ->
    _ = emqx:hook('client.authenticate', {?MODULE, authenticate, []}, ?HOOK_PRIORITY),
    _ = emqx_ctl:register_command(?APP, {emqx_plugin_redis_auth_cli, cmd}),
    ?LOG_INFO("redis_auth_plugin_started hook=client.authenticate priority=~p",
              [?HOOK_PRIORITY]),
    ok.

unload() ->
    ?LOG_INFO("redis_auth_plugin_stopping"),
    _ = emqx:unhook('client.authenticate', {?MODULE, authenticate}),
    _ = emqx_ctl:unregister_command(?APP),
    ?LOG_INFO("redis_auth_plugin_stopped"),
    ok.

%%--------------------------------------------------------------------
%% 'client.authenticate' hook callback
%%
%% The hook is a fold, the callback receives (ClientInfo, AuthResult).
%% Returning {stop, NewAcc} ends the chain with NewAcc as the result.
%%--------------------------------------------------------------------

authenticate(ClientInfo, AuthResult) ->
    case do_verify(ClientInfo) of
        allow ->
            log_auth(success, ClientInfo, allow),
            {stop, AuthResult#{auth_result => success,
                               anonymous => false,
                               is_superuser => false}};
        {deny, Reason} ->
            log_auth(failure, ClientInfo, Reason),
            {stop, AuthResult#{auth_result => not_authorized, anonymous => false}}
    end.

%% Authentication results are written to a dedicated audit file. The level
%% of each kind of event is configurable and defaults to none for successes
%% and warning for failures.
log_auth(Result, ClientInfo, Reason) ->
    Fields = [{result, Result},
              {clientid, maps:get(clientid, ClientInfo, undefined)},
              {username, maps:get(username, ClientInfo, undefined)},
              {peerhost, maps:get(peerhost, ClientInfo, undefined)},
              {peerport, peer_port()},
              {sockport, maps:get(sockport, ClientInfo, undefined)},
              {reason, Reason}],
    emqx_plugin_redis_auth_log:log(Result, Fields).

%% ClientInfo carries the listener port (`sockport') but not the client's
%% source port: emqx_channel drops it when building the client info. The
%% connection process keeps the formatted peername ("ip:port") in its logger
%% metadata, and the hook runs in that same process, so the source port can
%% be read from there.
peer_port() ->
    case logger:get_process_metadata() of
        #{peername := Peername} when is_list(Peername) ->
            case string:split(Peername, ":", trailing) of
                [_Host, Port] -> to_port(Port);
                _ -> undefined
            end;
        _ ->
            undefined
    end.

to_port(Str) ->
    try
        list_to_integer(Str)
    catch
        _:_ -> undefined
    end.

%%--------------------------------------------------------------------
%% Verify logic (mirrors the Java AuthService.authDeviceInRedis)
%%--------------------------------------------------------------------

do_verify(ClientInfo) ->
    ClientId = cred_bin(maps:get(clientid, ClientInfo, undefined)),
    Username = cred_bin(maps:get(username, ClientInfo, undefined)),
    Password = cred_bin(maps:get(password, ClientInfo, undefined)),
    case ClientId =:= <<>> orelse Username =:= <<>> orelse Password =:= <<>> of
        true ->
            {deny, conn_info_incomplete};
        false ->
            do_verify(ClientId, Username, Password)
    end.

do_verify(ClientId, Username, Password) ->
    WhiteList = conf_bin_list(white_service_list, ?DEFAULT_WHITE_LIST),
    case lists:member(Username, WhiteList) of
        true ->
            ?LOG_DEBUG("redis_auth_whitelist_allow username=~p", [Username]),
            allow;
        false ->
            case Username =:= conf_bin(unm_username, <<"UNM2000">>) of
                true -> verify_unm_password(Password);
                false -> verify_device(ClientId)
            end
    end.

%% UNM2000: AES/CBC/NoPadding with a zero IV, decrypt and compare.
verify_unm_password(Password) ->
    Key = conf_bin(aes_key, <<"Fiber#Aes@369069">>),
    Expected = conf_bin(unm_expected_password, <<"Umc2024@Adm">>),
    case aes_decrypt(Password, Key) of
        {ok, Expected} ->
            allow;
        _ ->
            {deny, unm_password_mismatch}
    end.

verify_device(ClientId) ->
    RealMac = get_real_mac(ClientId),
    SnKey = <<(conf_bin(snindex_key_prefix, <<"snindex:">>))/binary, RealMac/binary>>,
    case redis_q(["GET", SnKey]) of
        {ok, undefined} ->
            {deny, device_not_exists};
        {ok, ApId} when is_binary(ApId) ->
            case has_keepalive_tag(ClientId) of
                true -> verify_keepalive(ApId);
                false -> allow
            end;
        {error, Reason} ->
            degrade_on_redis_error(Reason)
    end.

verify_keepalive(ApId) ->
    ApKey = <<(conf_bin(ap_key_prefix, <<"ap:">>))/binary, ApId/binary>>,
    Field = conf_bin(ap_status_field, <<"status">>),
    Offline = conf_bin(ap_status_offline, <<"0">>),
    case redis_q(["HGET", ApKey, Field]) of
        %% missing status -> unknown -> allow (same as Java)
        {ok, undefined} ->
            allow;
        %% an existing field with an empty value is unknown as well (Java
        %% checks `status == null || status.isEmpty()')
        {ok, <<>>} ->
            allow;
        %% main channel offline -> the keepalived channel is allowed
        {ok, Offline} ->
            allow;
        %% any other status (online) -> deny, the main channel is online
        {ok, _Online} ->
            {deny, main_channel_online};
        {error, Reason} ->
            degrade_on_redis_error(Reason)
    end.

%% The Java implementation catches redis errors and falls back to 'allow' so
%% that an unavailable redis does not lock out every device.
degrade_on_redis_error(Reason) ->
    log_redis_error(Reason),
    case conf_bool(fallback_allow_on_redis_error, true) of
        true ->
            allow;
        false ->
            {deny, redis_error}
    end.

%% A lost connection is already reported at warning level by the connection
%% wrapper (on the failure transition), so it is only logged at debug here to
%% avoid one warning line per authentication attempt during an outage.
log_redis_error(no_connection) ->
    ?LOG_DEBUG("redis_auth_redis_unavailable");
log_redis_error(Reason) ->
    ?LOG_WARNING("redis_auth_redis_error reason=~p", [Reason]).

%%--------------------------------------------------------------------
%% Helpers (mirrors the Java CommonUtils.getRealMac)
%%--------------------------------------------------------------------

get_real_mac(ClientId) ->
    case has_keepalive_tag(ClientId) of
        false ->
            ClientId;
        true ->
            %% Java: split("-") and take the first part only when there are
            %% exactly 2 segments.
            case binary:split(ClientId, <<"-">>, [global]) of
                [Mac, _TagPart] -> Mac;
                _ -> ClientId
            end
    end.

has_keepalive_tag(ClientId) ->
    Tag = conf_bin(keepalived_tag, <<"Tr369KeepAlived">>),
    Tag =/= <<>> andalso binary:match(ClientId, Tag) =/= nomatch.

cred_bin(undefined) -> <<>>;
cred_bin(Bin) when is_binary(Bin) -> Bin;
cred_bin(Other) -> iolist_to_binary(Other).

%% AES/CBC/NoPadding with a zero IV; the plaintext is zero padded.
aes_decrypt(Base64Text, KeyBin) ->
    try
        Cipher = base64:decode(Base64Text),
        IV = <<0:128>>,
        Padded = crypto:crypto_one_time(aes_128_cbc, KeyBin, IV, Cipher, false),
        {ok, trim_zero_padding(Padded)}
    catch
        _:_ ->
            {error, decrypt_failed}
    end.

trim_zero_padding(Bin) ->
    trim_zero_padding(byte_size(Bin), Bin).

trim_zero_padding(0, _Bin) ->
    <<>>;
trim_zero_padding(Size, Bin) ->
    case binary:at(Bin, Size - 1) of
        0 -> trim_zero_padding(Size - 1, Bin);
        _ -> binary:part(Bin, 0, Size)
    end.

%%--------------------------------------------------------------------
%% Redis access
%%
%% eredis has no built-in pool: the supervisor starts `redis_pool_size'
%% connection wrappers and commands are hashed across them.
%%--------------------------------------------------------------------

redis_q(Command) ->
    Timeout = conf_int(redis_query_timeout_ms, 2000),
    case pick_client(Command) of
        undefined ->
            {error, no_connection};
        Pid ->
            emqx_plugin_redis_auth_conn:q(Pid, Command, Timeout)
    end.

ping() ->
    redis_q(["PING"]).

pick_client(Command) ->
    case redis_pids() of
        [] -> undefined;
        Pids -> lists:nth(erlang:phash2(Command, length(Pids)) + 1, Pids)
    end.

redis_pids() ->
    try
        [Pid
         || {Id, Pid, _Type, _Mods} <- supervisor:which_children(emqx_plugin_redis_auth_sup),
            is_pid(Pid),
            is_conn_id(Id)]
    catch
        _:_ -> []
    end.

is_conn_id({conn, _}) -> true;
is_conn_id(_) -> false.

%%--------------------------------------------------------------------
%% Config access
%%
%% Values are read from the application environment, which EMQX fills from
%% `etc/plugins/emqx_plugin_redis_auth.conf' through the cuttlefish schema in
%% `priv/emqx_plugin_redis_auth.schema'.
%%--------------------------------------------------------------------

%% Consumed by emqx_plugin_redis_auth_sup to build the connection children.
redis_options() ->
    #{host => conf_bin(redis_host, <<"127.0.0.1">>),
      port => conf_int(redis_port, 6379),
      database => conf_int(redis_database, 0),
      password => conf_bin(redis_password, <<>>),
      pool_size => conf_int(redis_pool_size, 8),
      reconnect_sleep => conf_int(redis_reconnect_sleep_ms, 1000),
      connect_timeout => conf_int(redis_connect_timeout_ms, 5000)}.

get_config() ->
    lists:sort([{Key, mask(Key, Value)} || {Key, Value} <- application:get_all_env(?APP)]).

mask(Key, _Value) when Key =:= redis_password;
                       Key =:= aes_key;
                       Key =:= unm_expected_password ->
    <<"******">>;
mask(_Key, Value) ->
    Value.

conf_bin(Key, Default) ->
    case application:get_env(?APP, Key, undefined) of
        undefined -> Default;
        Value when is_binary(Value) -> Value;
        Value when is_list(Value) -> iolist_to_binary(Value);
        _Value -> Default
    end.

conf_int(Key, Default) ->
    case application:get_env(?APP, Key, undefined) of
        undefined -> Default;
        Value when is_integer(Value) -> Value;
        Value when is_binary(Value) -> to_integer(Value, Default);
        Value when is_list(Value) -> to_integer(list_to_binary(Value), Default);
        _Value -> Default
    end.

conf_bool(Key, Default) ->
    case application:get_env(?APP, Key, undefined) of
        undefined -> Default;
        true -> true;
        false -> false;
        <<"true">> -> true;
        <<"false">> -> false;
        <<"on">> -> true;
        <<"off">> -> false;
        "true" -> true;
        "false" -> false;
        "on" -> true;
        "off" -> false;
        _Value -> Default
    end.

conf_bin_list(Key, Default) ->
    case application:get_env(?APP, Key, undefined) of
        undefined ->
            Default;
        Value when is_binary(Value) ->
            split_on_comma(Value);
        Value when is_list(Value) ->
            case Value =/= [] andalso lists:all(fun is_binary/1, Value) of
                true -> Value;
                false -> split_on_comma(iolist_to_binary(Value))
            end;
        _Value ->
            Default
    end.

split_on_comma(Bin) ->
    [list_to_binary(string:trim(Token))
     || Token <- string:tokens(binary_to_list(Bin), ","),
        string:trim(Token) =/= ""].

to_integer(Bin, Default) ->
    try
        binary_to_integer(Bin)
    catch
        _:_ -> Default
    end.
