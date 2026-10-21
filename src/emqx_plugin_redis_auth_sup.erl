%%--------------------------------------------------------------------
%% EMQX 4.4 Redis authentication plugin - supervisor.
%%
%% eredis (wooga) has no built-in connection pool: we start
%% `redis_pool_size` connections and the caller hashes the redis command
%% (and therefore the redis key) across them, so the same key always lands
%% on the same connection.
%%
%% Each child is an `emqx_plugin_redis_auth_conn' wrapper rather than a bare
%% eredis client, because a bare client refuses to start when redis is
%% unreachable (see the wrapper for details).
%%--------------------------------------------------------------------

-module(emqx_plugin_redis_auth_sup).

-behaviour(supervisor).

-include_lib("kernel/include/logger.hrl").

-export([start_link/0]).

-export([init/1]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    Opts = emqx_plugin_redis_auth:redis_options(),
    #{host := Host, port := Port, database := Database, pool_size := PoolSize} = Opts,
    ?LOG_INFO("redis_auth_clients_starting host=~s port=~p database=~p pool_size=~p",
              [Host, Port, Database, PoolSize]),
    ChildSpecs =
        [#{id => auth_log,
           start => {emqx_plugin_redis_auth_log, start_link, []},
           restart => permanent,
           shutdown => 5000,
           type => worker,
           modules => [emqx_plugin_redis_auth_log]}
         | [#{id => {conn, I},
             start => {emqx_plugin_redis_auth_conn, start_link, [Opts]},
             restart => permanent,
             shutdown => 5000,
             type => worker,
             modules => [emqx_plugin_redis_auth_conn]}
            || I <- lists:seq(1, PoolSize)]],
    {ok, {{one_for_one, 10, 10}, ChildSpecs}}.
