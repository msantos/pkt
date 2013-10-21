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

-include("pkt.hrl").

-export([codec/1]).

-spec codec(binary()) -> {#sctp{}, []}.
codec(<<SPort:16, DPort:16, VTag:32, Sum:32, Payload/binary>>) ->
    SCTP = #sctp{
        sport = SPort, dport = DPort, vtag = VTag,
        sum = Sum, chunks = sctp_decode_chunks(Payload, [])
    },
    {SCTP, []}.

-spec sctp_decode_chunks(binary(), list()) -> [#sctp_chunk{}].
sctp_decode_chunks(<<>>, Acc) -> Acc;
sctp_decode_chunks(<<Type:8, Flags:8, Length:16, Rest/binary>>, Acc) ->
    L = case Length rem 4 of
        0 -> % No padding bytes
            Length - 4;
        N when N =< 3 -> % pad should be no more than 3 bytes
            Length + (4 - N) - 4
    end,
    case Length - 4 =< L of
        true ->
            [sctp_chunk(Type, Flags, Length, Rest) | Acc];
        false ->
            <<Payload:L/binary-unit:8, Tail/binary>> = Rest,
            sctp_decode_chunks(Tail, [sctp_chunk(Type, Flags, Length, Payload) | Acc])
    end.

-spec sctp_chunk(byte(), byte(), non_neg_integer(), binary()) -> #sctp_chunk{}.
sctp_chunk(Ctype, Cflags, Clen, Payload) ->
	#sctp_chunk{
        type = Ctype, flags = Cflags, len = Clen - 4,
        payload = sctp_chunk_payload(Ctype, Payload)
    }.

-spec sctp_chunk_payload(non_neg_integer(), binary()) -> #sctp_chunk_data{} | binary().
sctp_chunk_payload(?SCTP_CHUNK_DATA, <<Tsn:32, Sid:16, Ssn:16, Ppi:32, Data/binary>>) ->
	#sctp_chunk_data{tsn = Tsn, sid = Sid, ssn = Ssn, ppi = Ppi, data = Data};
sctp_chunk_payload(?SCTP_CHUNK_INIT, <<Itag:32, Arwnd:32, OutStreams:16, InStreams:16, Tsn:32, Rest/binary>>) ->
    #sctp_chunk_init{
        itag = Itag,
        a_rwnd = Arwnd,
        outbound_streams = OutStreams,
        inbound_streams = InStreams,
        tsn = Tsn,
        params = sctp_init_params(Rest, [])
    };
sctp_chunk_payload(?SCTP_CHUNK_INIT_ACK, <<Itag:32, Arwnd:32, OutStreams:16, InStreams:16, Tsn:32, Rest/binary>>) ->
    #sctp_chunk_init_ack{
        itag = Itag,
        a_rwnd = Arwnd,
        outbound_streams = OutStreams,
        inbound_streams = InStreams,
        tsn = Tsn,
        params = sctp_init_params(Rest, [])
    };
sctp_chunk_payload(?SCTP_CHUNK_SACK, <<TSN_ACK:32, Arwnd:32, GapsN:16, DuplicateTSN:16, Rest/binary>>) ->
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
sctp_chunk_payload(?SCTP_CHUNK_COOKIE_ECHO, Cookie) ->
    #sctp_chunk_cookie_echo{cookie = Cookie};
sctp_chunk_payload(?SCTP_CHUNK_COOKIE_ACK, <<>>) ->
    #sctp_chunk_cookie_ack{};
sctp_chunk_payload(?SCTP_CHUNK_HEARTBEAT, <<Type:16, _Length:16, Info/binary>>) ->
    #sctp_chunk_heartbeat{type = Type, info = Info};
sctp_chunk_payload(?SCTP_CHUNK_HEARTBEAT_ACK, <<Type:16, _Length:16, Info/binary>>) ->
    #sctp_chunk_heartbeat_ack{type = Type, info = Info};
sctp_chunk_payload(?SCTP_CHUNK_SHUTDOWN, <<TSN_ACK:32>>) ->
    #sctp_chunk_shutdown{tsn_ack = TSN_ACK};
sctp_chunk_payload(?SCTP_CHUNK_SHUTDOWN_ACK, <<>>) ->
    #sctp_chunk_shutdown_ack{};
sctp_chunk_payload(?SCTP_CHUNK_SHUTDOWN_COMPLETE, <<>>) ->
    #sctp_chunk_shutdown_complete{};
sctp_chunk_payload(?SCTP_CHUNK_ABORT, Errors) ->
    #sctp_chunk_abort{error_causes = sctp_error_causes(Errors, [])};
sctp_chunk_payload(_, Data) ->
	Data.

sctp_init_params(<<>>, Acc) -> Acc;

%% IPv4 Address Parameter
sctp_init_params(<<5:16, 8:16, A:8, B:8, C:8, D:8, Rest/binary>>, Acc) ->
    sctp_init_params(Rest, [{ipv4, {A, B, C, D}} | Acc]);
%% IPv6 Address Parameter
sctp_init_params(<<6:16, 20:16, Value:16/binary-unit:8, Rest/binary>>, Acc) ->
    IP = list_to_tuple([N || <<N:16>> <= Value]),
    sctp_init_params(Rest, [{ipv6, IP} | Acc]);
%% State cookie
sctp_init_params(<<7:16, Length:16, Rest/binary>>, Acc) ->
    L = Length - 4,
    <<Cookie:L/binary-unit:8, Tail/binary>> = Rest,
    sctp_init_params(Tail, [{state_cookie, Cookie} | Acc]);
%% Unrecognized Parameter
sctp_init_params(<<8:16, Length:16, Rest/binary>>, Acc) ->
    L = Length - 4,
    <<Parameter:L/binary-unit:8, Tail/binary>> = Rest,
    sctp_init_params(Tail, [{unrecognized, Parameter} | Acc]);
%% Cookie Preservative
sctp_init_params(<<9:16, 8:16, Value:32, Rest/binary>>, Acc) ->
    sctp_init_params(Rest, [{cookie, Value} | Acc]);
%% Host Name Address
sctp_init_params(<<11:16, Length:16, Rest/binary>>, Acc) ->
    L = Length - 4,
    <<Hostname:L/binary-unit:8, Tail/binary>> = Rest,
    sctp_init_params(Tail, [{hostname, Hostname} | Acc]);
%% Supported Address Types
sctp_init_params(<<12:16, Length:16, Rest/binary>>, Acc) ->
    AddressType =
        fun(5) -> ipv4;
           (6) -> ipv6;
           (11) -> hostname
    end,
    case Length rem 4 of
        0 ->
            <<Value:16, Tail/binary>> = Rest,
            sctp_init_params(Tail, [{address_type, AddressType(Value)} | Acc]);
        N ->
            <<Value:16, _Padding:N/binary-unit:8, Tail/binary>> = Rest,
            sctp_init_params(Tail, [{address_type, AddressType(Value)} | Acc])
    end;
%% Ignore ECN and Forward TSN parameters
sctp_init_params(_, Acc) -> Acc.

sctp_error_causes(<<>>, Acc) ->
    Acc;
sctp_error_causes(<<Code:16, Length:16, Rest/binary>>, Acc) ->
    L = Length - 4,
    <<Opts:L/binary-unit:8, Tail/binary>> = Rest,
    sctp_error_causes(Tail, [sctp_error(Code, L, Opts) | Acc]).

sctp_error(1, _Length, <<Ident:16, _Reserved:8>>) ->
    #sctp_error_cause{
        code = 1,
        descr = sctp_format_error(1),
        opts = [
            {stream_identifier, Ident}
        ]
    };
sctp_error(12, Length, Opts) ->
    <<Reason:Length/binary-unit:8>> = Opts,
    #sctp_error_cause{
        code = 12,
        descr = sctp_format_error(12),
        opts = [
            {abort_reason, Reason}
        ]
    };
%% FIXME: add more error causes
sctp_error(Code, _Length, Opts) ->
    #sctp_error_cause{
        code = Code,
        descr = sctp_format_error(Code),
        opts = [
            {data = Opts}
        ]
    }.

sctp_format_error(1) ->
    "Invalid Stream Identifier";
sctp_format_error(2) ->
    "Missing Mandatory Parameter";
sctp_format_error(3) ->
    "Stale Cookie Error";
sctp_format_error(4) ->
    "Out of Resource";
sctp_format_error(5) ->
    "Unresolvable Address";
sctp_format_error(6) ->
    "Unrecognized Chunk Type";
sctp_format_error(7) ->
    "Invalid Mandatory Parameter";
sctp_format_error(8) ->
    "Unrecognized Parameters";
sctp_format_error(9) ->
    "No User Data";
sctp_format_error(10) ->
    "Cookie Received While Shutting Down";
sctp_format_error(11) ->
    "Restart of an Association with New Addresses";
sctp_format_error(12) ->
    "User Initiated Abort";
sctp_format_error(13) ->
    "Protocol Violation".
