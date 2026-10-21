%%--------------------------------------------------------------------
%% EMQX 4.4 Redis authentication plugin - application callback.
%%--------------------------------------------------------------------

-module(emqx_plugin_redis_auth_app).

-behaviour(application).

-emqx_plugin(auth).

-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
    {ok, Sup} = emqx_plugin_redis_auth_sup:start_link(),
    emqx_plugin_redis_auth:load(application:get_all_env()),
    {ok, Sup}.

stop(_State) ->
    emqx_plugin_redis_auth:unload().
