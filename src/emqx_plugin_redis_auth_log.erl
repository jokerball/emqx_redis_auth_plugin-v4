%%--------------------------------------------------------------------
%% EMQX 4.4 Redis authentication plugin - audit log writer.
%%
%% Authentication results go to a dedicated file instead of the EMQX log.
%% A separate gen_server is used (rather than an extra `logger' handler)
%% so that the events do not show up twice: adding a handler would leave
%% the default EMQX handlers receiving the same events as well.
%%
%% Writes are casts, so the authentication path never blocks on disk I/O.
%% The file is rotated by size; `auth_log_file' can be set to an empty
%% string to disable the audit log. The level used for each event is
%% configurable (`auth_log_success_level' / `auth_log_failure_level'), and
%% a level of `none' drops that kind of event.
%%--------------------------------------------------------------------

-module(emqx_plugin_redis_auth_log).

-behaviour(gen_server).

-include_lib("kernel/include/logger.hrl").

-export([start_link/0, log/2]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2,
         code_change/3]).

-define(APP, emqx_plugin_redis_auth).

-define(DEFAULT_FILE, <<"log/emqx_plugin_redis_auth.log">>).
-define(DEFAULT_MAX_SIZE, 10 * 1024 * 1024).
-define(DEFAULT_MAX_FILES, 5).

-record(state, {fd :: file:io_device() | undefined,
                path :: binary(),
                max_bytes :: pos_integer(),
                max_files :: pos_integer(),
                success_level = none :: atom(),
                failure_level = warning :: atom(),
                size = 0 :: non_neg_integer(),
                open_error_logged = false :: boolean()}).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% Result is `success' | `failure'.
log(Result, Fields) ->
    gen_server:cast(?MODULE, {write, Result, Fields}).

%%--------------------------------------------------------------------
%% gen_server callbacks
%%--------------------------------------------------------------------

init([]) ->
    Path = conf(auth_log_file, ?DEFAULT_FILE),
    MaxBytes = max(1, conf_int(auth_log_max_size, ?DEFAULT_MAX_SIZE)),
    MaxFiles = max(1, conf_int(auth_log_max_files, ?DEFAULT_MAX_FILES)),
    State = open(#state{path = Path,
                        max_bytes = MaxBytes,
                        max_files = MaxFiles,
                        success_level = conf_level(auth_log_success_level, none),
                        failure_level = conf_level(auth_log_failure_level, warning)}),
    {ok, State}.

handle_call(_Req, _From, State) ->
    {reply, ignored, State}.

handle_cast({write, Result, Fields}, State) ->
    case level_for(Result, State) of
        none -> {noreply, State};
        Level -> {noreply, do_write(format_line(Level, Fields), State)}
    end;
handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #state{fd = undefined}) ->
    ok;
terminate(_Reason, #state{fd = Fd}) ->
    _ = file:close(Fd),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%--------------------------------------------------------------------
%% Internal
%%--------------------------------------------------------------------

do_write(_Line, State = #state{path = <<>>}) ->
    State;
do_write(Line, State0 = #state{fd = undefined}) ->
    case open(State0) of
        State = #state{fd = undefined} -> State;
        State -> do_write(Line, State)
    end;
do_write(Line, State = #state{fd = Fd, size = Size, path = Path}) ->
    case file:write(Fd, Line) of
        ok ->
            maybe_rotate(State#state{size = Size + iolist_size(Line)});
        {error, Reason} ->
            ?LOG_WARNING("redis_auth_log_write_failed path=~s reason=~p",
                         [Path, Reason]),
            _ = file:close(Fd),
            State#state{fd = undefined}
    end.

open(State = #state{path = <<>>}) ->
    State#state{fd = undefined};
open(State = #state{path = Path}) ->
    _ = filelib:ensure_dir(Path),
    case file:open(Path, [append, raw, binary]) of
        {ok, Fd} ->
            ?LOG_INFO("redis_auth_audit_log_opened path=~s", [Path]),
            State#state{fd = Fd, size = filelib:file_size(Path),
                        open_error_logged = false};
        {error, Reason} ->
            case State#state.open_error_logged of
                true -> ok;
                false ->
                    ?LOG_WARNING("redis_auth_audit_log_open_failed path=~s reason=~p",
                                 [Path, Reason])
            end,
            State#state{fd = undefined, open_error_logged = true}
    end.

maybe_rotate(State = #state{size = Size, max_bytes = MaxBytes})
  when Size >= MaxBytes ->
    rotate(State);
maybe_rotate(State) ->
    State.

rotate(State = #state{fd = Fd, path = Path, max_files = MaxFiles}) ->
    _ = file:close(Fd),
    _ = file:delete(rotated(Path, MaxFiles)),
    lists:foreach(
      fun(I) ->
              case filelib:is_regular(rotated(Path, I)) of
                  true -> _ = file:rename(rotated(Path, I), rotated(Path, I + 1));
                  false -> ok
              end
      end, lists:seq(MaxFiles - 1, 1, -1)),
    _ = file:rename(Path, rotated(Path, 1)),
    open(State#state{fd = undefined, size = 0}).

rotated(Path, N) ->
    <<Path/binary, ".", (integer_to_binary(N))/binary>>.

format_line(Level, Fields) ->
    Timestamp = list_to_binary(
                  calendar:system_time_to_rfc3339(
                    erlang:system_time(millisecond),
                    [{unit, millisecond}, {offset, "Z"}])),
    [Timestamp, <<" [">>, atom_to_binary(Level, utf8), <<"] ">>,
     lists:join(<<" ">>,
                [[atom_to_binary(Key, utf8), <<"=">>, format_value(Value)]
                 || {Key, Value} <- Fields]),
     <<"\n">>].

format_value(Value) when is_binary(Value) ->
    Value;
format_value(Value) when is_atom(Value) ->
    atom_to_binary(Value, utf8);
format_value(Value) when is_integer(Value) ->
    integer_to_binary(Value);
format_value(Value) ->
    iolist_to_binary(io_lib:format("~0p", [Value])).

level_for(success, #state{success_level = Level}) -> Level;
level_for(failure, #state{failure_level = Level}) -> Level.

conf(Key, Default) ->
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

conf_level(Key, Default) ->
    case application:get_env(?APP, Key, undefined) of
        undefined -> Default;
        Value when is_atom(Value) -> valid_level(Value, Default);
        Value when is_binary(Value) -> level_from_binary(Value, Default);
        Value when is_list(Value) -> level_from_binary(list_to_binary(Value), Default);
        _Value -> Default
    end.

level_from_binary(<<"debug">>, _Default) -> debug;
level_from_binary(<<"info">>, _Default) -> info;
level_from_binary(<<"notice">>, _Default) -> notice;
level_from_binary(<<"warning">>, _Default) -> warning;
level_from_binary(<<"error">>, _Default) -> error;
level_from_binary(<<"none">>, _Default) -> none;
level_from_binary(_Value, Default) -> Default.

valid_level(Level, _Default) when Level =:= debug; Level =:= info; Level =:= notice;
                                   Level =:= warning; Level =:= error; Level =:= none ->
    Level;
valid_level(_Level, Default) ->
    Default.

to_integer(Bin, Default) ->
    try
        binary_to_integer(Bin)
    catch
        _:_ -> Default
    end.
