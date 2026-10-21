%%--------------------------------------------------------------------
%% EMQX 4.4 Redis authentication plugin - `emqx_ctl redis_auth <cmd>`.
%%--------------------------------------------------------------------

-module(emqx_plugin_redis_auth_cli).

-export([cmd/1]).

cmd(["get-config"]) ->
    Config = maps:from_list(
               [{atom_to_binary(Key, utf8), Value}
                || {Key, Value} <- emqx_plugin_redis_auth:get_config()]),
    emqx_ctl:print("~s~n", [emqx_json:encode(Config)]);
cmd(["status"]) ->
    case emqx_plugin_redis_auth:ping() of
        {ok, <<"PONG">>} ->
            emqx_ctl:print("Redis auth: running (PONG)~n");
        Other ->
            emqx_ctl:print("Redis auth: unavailable (~p)~n", [Other])
    end;
cmd(_) ->
    emqx_ctl:usage([{"emqx_plugin_redis_auth get-config", "get current plugin config"},
                    {"emqx_plugin_redis_auth status", "check Redis connectivity"}]).
