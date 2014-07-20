%% Copyright (c) 2009-2013, Michael Santos <michael.santos@gmail.com>
%% All rights reserved.
%%
%% Redistribution and use in source and binary forms, with or without
%% modification, are permitted provided that the following conditions
%% are met:
%%
%% Redistributions of source code must retain the above copyright
%% notice, this list of conditions and the following disclaimer.
%%
%% Redistributions in binary form must reproduce the above copyright
%% notice, this list of conditions and the following disclaimer in the
%% documentation and/or other materials provided with the distribution.
%%
%% Neither the name of the author nor the names of its contributors
%% may be used to endorse or promote products derived from this software
%% without specific prior written permission.
%%
%% THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
%% "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
%% LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
%% FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
%% COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
%% INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
%% BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
%% LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
%% CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
%% LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
%% ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
%% POSSIBILITY OF SUCH DAMAGE.
-module(pkt_sctp).

-include("pkt_sctp.hrl").

-export([codec/1]).

-spec codec(binary()) -> {#sctp{}, binary()}.
codec(<<SPort:16, DPort:16, VTag:32, Sum:32, Payload/binary>>) ->
    {Chunks, Other} = decode_chunks(Payload, []),
    SCTP = #sctp{
        sport = SPort, dport = DPort, vtag = VTag,
        sum = Sum, chunks = Chunks
    },
    {SCTP, Other}.

%% Internal functions

decode_chunks(<<>>, Acc) -> {Acc, <<>>};
decode_chunks(<<Type:8, Flags:8, Length:16, Rest/binary>>, Acc) ->
    {L, Pad} = case Length rem 4 of
        0 -> % No padding bytes
            {Length - 4, 0};
        N when N =< 3 -> % pad should be no more than 3 bytes
            {Length - 4, (4 - N) * 8}
    end,
    <<Payload:L/binary-unit:8, _:Pad, Tail/binary>> = Rest,
    decode_chunks(Tail, [chunk(Type, Flags, Length, Payload) | Acc]);
%% Ignore other bytes which are not SCTP chunks (VSS, ...)
decode_chunks(Other, Acc) -> {Acc, Other}.

-spec chunk(byte(), byte(), non_neg_integer(), binary()) -> #sctp_chunk{}.
chunk(Type, Flags, Len, Payload) ->
	#sctp_chunk{
        type = Type, flags = Flags, len = Len - 4,
        payload = chunk_payload(Type, Payload)
    }.

-spec chunk_payload(non_neg_integer(), binary()) -> #sctp_chunk_data{} | binary().
chunk_payload(?SCTP_CHUNK_DATA, <<Tsn:32, Sid:16, Ssn:16, Ppi:32, Data/binary>>) ->
	#sctp_chunk_data{tsn = Tsn, sid = Sid, ssn = Ssn, ppi = Ppi, data = Data};
chunk_payload(?SCTP_CHUNK_INIT, <<Itag:32, Arwnd:32, OutStreams:16, InStreams:16, Tsn:32, Rest/binary>>) ->
    #sctp_chunk_init{
        itag = Itag,
        a_rwnd = Arwnd,
        outbound_streams = OutStreams,
        inbound_streams = InStreams,
        tsn = Tsn,
        params = init_params(Rest, [])
    };
chunk_payload(?SCTP_CHUNK_INIT_ACK, <<Itag:32, Arwnd:32, OutStreams:16, InStreams:16, Tsn:32, Rest/binary>>) ->
    #sctp_chunk_init_ack{
        itag = Itag,
        a_rwnd = Arwnd,
        outbound_streams = OutStreams,
        inbound_streams = InStreams,
        tsn = Tsn,
        params = init_params(Rest, [])
    };
chunk_payload(?SCTP_CHUNK_SACK, <<TSN_ACK:32, Arwnd:32, GapsN:16, DuplicateTSN:16, Rest/binary>>) ->
    GapsLength = GapsN * 4, %% Gap Ack start (16), Gap Ack end (16)
    <<Gaps:GapsLength/binary-unit:8, TSNs/binary>> = Rest,
    #sctp_chunk_sack{
        tsn_ack = TSN_ACK,
        a_rwnd = Arwnd,
        number_gap_ack_blocks = GapsN,
        number_duplicate_tsn = DuplicateTSN,
        gap_ack_blocks = [{Start, End} || <<Start:16, End:16>> <= Gaps],
        duplicate_tsns = [T || <<T:32>> <= TSNs]
    };
chunk_payload(?SCTP_CHUNK_COOKIE_ECHO, Cookie) ->
    #sctp_chunk_cookie_echo{cookie = Cookie};
chunk_payload(?SCTP_CHUNK_COOKIE_ACK, <<>>) ->
    #sctp_chunk_cookie_ack{};
chunk_payload(?SCTP_CHUNK_HEARTBEAT, <<Type:16, _Length:16, Info/binary>>) ->
    #sctp_chunk_heartbeat{type = Type, info = Info};
chunk_payload(?SCTP_CHUNK_HEARTBEAT_ACK, <<Type:16, _Length:16, Info/binary>>) ->
    #sctp_chunk_heartbeat_ack{type = Type, info = Info};
chunk_payload(?SCTP_CHUNK_SHUTDOWN, <<TSN_ACK:32>>) ->
    #sctp_chunk_shutdown{tsn_ack = TSN_ACK};
chunk_payload(?SCTP_CHUNK_SHUTDOWN_ACK, <<>>) ->
    #sctp_chunk_shutdown_ack{};
chunk_payload(?SCTP_CHUNK_SHUTDOWN_COMPLETE, <<>>) ->
    #sctp_chunk_shutdown_complete{};
chunk_payload(?SCTP_CHUNK_ABORT, Errors) ->
    #sctp_chunk_abort{error_causes = error_causes(Errors, [])};
chunk_payload(_, Data) ->
	Data.

init_params(<<>>, Acc) -> Acc;

%% IPv4 Address Parameter
init_params(<<5:16, 8:16, A:8, B:8, C:8, D:8, Rest/binary>>, Acc) ->
    init_params(Rest, [{ipv4, {A, B, C, D}} | Acc]);
%% IPv6 Address Parameter
init_params(<<6:16, 20:16, Value:16/binary-unit:8, Rest/binary>>, Acc) ->
    IP = list_to_tuple([N || <<N:16>> <= Value]),
    init_params(Rest, [{ipv6, IP} | Acc]);
%% State cookie
init_params(<<7:16, Length:16, Rest/binary>>, Acc) ->
    L = Length - 4,
    <<Cookie:L/binary-unit:8, Tail/binary>> = Rest,
    init_params(Tail, [{state_cookie, Cookie} | Acc]);
%% Unrecognized Parameter
init_params(<<8:16, Length:16, Rest/binary>>, Acc) ->
    L = Length - 4,
    <<Parameter:L/binary-unit:8, Tail/binary>> = Rest,
    init_params(Tail, [{unrecognized, Parameter} | Acc]);
%% Cookie Preservative
init_params(<<9:16, 8:16, Value:32, Rest/binary>>, Acc) ->
    init_params(Rest, [{cookie, Value} | Acc]);
%% Host Name Address
init_params(<<11:16, Length:16, Rest/binary>>, Acc) ->
    L = Length - 4,
    <<Hostname:L/binary-unit:8, Tail/binary>> = Rest,
    init_params(Tail, [{hostname, Hostname} | Acc]);
%% Supported Address Types
init_params(<<12:16, Length:16, Rest/binary>>, Acc) ->
    AddressType =
        fun(5) -> ipv4;
           (6) -> ipv6;
           (11) -> hostname
    end,
    L = Length - 4,
    <<Types:L/binary-unit:8, Tail/binary>> = Rest,
    init_params(Tail, [{address_types, [AddressType(V) || <<V:16>> <= Types]} | Acc]);
%% Ignore ECN and Forward TSN parameters
init_params(_, Acc) -> Acc.

error_causes(<<>>, Acc) ->
    Acc;
error_causes(<<Code:16, Length:16, Rest/binary>>, Acc) ->
    L = Length - 4,
    <<Opts:L/binary-unit:8, Tail/binary>> = Rest,
    error_causes(Tail, [sctp_error(Code, L, Opts) | Acc]).

sctp_error(1, _Length, <<Ident:16, _Reserved:8>>) ->
    #sctp_error_cause{
        code = 1,
        descr = format_error(1),
        opts = [
            {stream_identifier, Ident}
        ]
    };
sctp_error(12, Length, Opts) ->
    <<Reason:Length/binary-unit:8>> = Opts,
    #sctp_error_cause{
        code = 12,
        descr = format_error(12),
        opts = [
            {abort_reason, Reason}
        ]
    };
%% FIXME: add more error causes
sctp_error(Code, _Length, Opts) ->
    #sctp_error_cause{
        code = Code,
        descr = format_error(Code),
        opts = [
            {data, Opts}
        ]
    }.

%% TODO: Replace this by using gen_sctp:error_string/1
%% Full all of errors were added since R16B03
format_error(1) ->
    "Invalid Stream Identifier";
format_error(2) ->
    "Missing Mandatory Parameter";
format_error(3) ->
    "Stale Cookie Error";
format_error(4) ->
    "Out of Resource";
format_error(5) ->
    "Unresolvable Address";
format_error(6) ->
    "Unrecognized Chunk Type";
format_error(7) ->
    "Invalid Mandatory Parameter";
format_error(8) ->
    "Unrecognized Parameters";
format_error(9) ->
    "No User Data";
format_error(10) ->
    "Cookie Received While Shutting Down";
format_error(11) ->
    "Restart of an Association with New Addresses";
format_error(12) ->
    "User Initiated Abort";
format_error(13) ->
    "Protocol Violation".
