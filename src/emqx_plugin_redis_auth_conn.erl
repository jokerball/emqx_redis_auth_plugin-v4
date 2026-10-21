%%--------------------------------------------------------------------
%% EMQX 4.4 Redis authentication plugin - eredis connection wrapper.
%%
%% `eredis' connects synchronously in `init/1' and returns `{stop, Reason}'
%% when the server is unreachable, which would make this plugin's supervisor
%% give up and fail the whole plugin application. Wrapping the client keeps
%% the plugin running (and its `fallback_allow_on_redis_error' policy
%% effective) while Redis is down, and retries in the background.
%%
%% A cheap TCP probe runs before every (re)start so that a down Redis does
%% not produce one eredis crash report per retry. Once a client is up,
%% eredis takes care of reconnects by itself; this wrapper only restarts a
%% client that died.
%%--------------------------------------------------------------------

-module(emqx_plugin_redis_auth_conn).

-behaviour(gen_server).

-include_lib("kernel/include/logger.hrl").

-export([start_link/1, q/3, is_connected/1]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2,
         code_change/3]).

-record(state, {opts :: map(),
                client :: pid() | undefined,
                last_error :: term(),
                last_warn_ms = 0 :: integer()}).

%% Re-warn about an unchanged failure at most this often, so a long outage
%% stays visible without one line per retry per connection.
-define(WARN_INTERVAL_MS, 300000).

start_link(Opts) ->
    gen_server:start_link(?MODULE, [Opts], []).

q(Pid, Command, Timeout) ->
    try
        gen_server:call(Pid, {q, Command, Timeout}, Timeout + 1000)
    catch
        exit:{timeout, _} -> {error, timeout};
        exit:{noproc, _} -> {error, no_connection}
    end.

is_connected(Pid) ->
    try gen_server:call(Pid, is_connected, 1000)
    catch
        _:_ -> false
    end.

%%--------------------------------------------------------------------
%% gen_server callbacks
%%--------------------------------------------------------------------

init([Opts]) ->
    process_flag(trap_exit, true),
    {ok, connect(#state{opts = Opts})}.

handle_call({q, _Command, _Timeout}, _From, State = #state{client = undefined}) ->
    {reply, {error, no_connection}, State};
handle_call({q, Command, Timeout}, _From, State = #state{client = Client}) ->
    Reply = try
                eredis:q(Client, Command, Timeout)
            catch
                Class:Reason -> {error, {Class, Reason}}
            end,
    {reply, Reply, State};
handle_call(is_connected, _From, State = #state{client = Client}) ->
    {reply, is_pid(Client) andalso is_process_alive(Client), State};
handle_call(_Req, _From, State) ->
    {reply, ignored, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(connect, State) ->
    {noreply, connect(State)};
handle_info({'EXIT', Client, Reason}, State = #state{client = Client}) ->
    ?LOG_WARNING("redis_auth_client_down reason=~p", [Reason]),
    {noreply, connect(State#state{client = undefined, last_error = undefined,
                                  last_warn_ms = 0})};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #state{client = undefined}) ->
    ok;
terminate(_Reason, #state{client = Client}) ->
    _ = catch eredis:stop(Client),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%--------------------------------------------------------------------
%% Internal
%%--------------------------------------------------------------------

connect(State = #state{opts = Opts}) ->
    case probe(Opts) of
        ok ->
            case start_client(Opts) of
                {ok, Client} ->
                    State#state{client = Client, last_error = undefined};
                {error, Reason} ->
                    retry(Reason, State)
            end;
        {error, Reason} ->
            retry(Reason, State)
    end.

retry(Reason, State = #state{opts = Opts, last_error = LastError,
                             last_warn_ms = LastWarn}) ->
    RetryMs = maps:get(reconnect_sleep, Opts, 1000),
    Now = erlang:system_time(millisecond),
    %% A down redis must not produce one warning line per retry: warn on the
    %% failure transition, then re-warn every ?WARN_INTERVAL_MS while it lasts.
    Warn = Reason =/= LastError orelse Now - LastWarn >= ?WARN_INTERVAL_MS,
    case Warn of
        true ->
            ?LOG_WARNING("redis_auth_connect_failed reason=~p retry_in_ms=~p",
                         [Reason, RetryMs]);
        false ->
            ?LOG_DEBUG("redis_auth_connect_failed reason=~p", [Reason])
    end,
    _ = erlang:send_after(RetryMs, self(), connect),
    State#state{client = undefined,
                last_error = Reason,
                last_warn_ms = case Warn of true -> Now; false -> LastWarn end}.

probe(#{host := Host0, port := Port, connect_timeout := Timeout}) ->
    case gen_tcp:connect(host_to_list(Host0), Port,
                         [binary, {active, false}], Timeout) of
        {ok, Socket} ->
            _ = gen_tcp:close(Socket),
            ok;
        {error, Reason} ->
            {error, Reason}
    end.

start_client(#{host := Host0,
               port := Port,
               database := Database,
               password := Password,
               reconnect_sleep := ReconnectSleep,
               connect_timeout := ConnectTimeout}) ->
    %% eredis only accepts a string host (it is handed to inet:parse_address/1).
    case eredis:start_link(host_to_list(Host0), Port, Database, Password,
                           ReconnectSleep, ConnectTimeout) of
        {ok, Client} -> {ok, Client};
        {error, Reason} -> {error, Reason}
    end.

host_to_list(Host) when is_binary(Host) -> binary_to_list(Host);
host_to_list(Host) -> Host.
