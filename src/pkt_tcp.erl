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
-module(pkt_tcp).

-include("pkt_tcp.hrl").

-export([
        codec/1,
        tcp_options/1
    ]).

codec(
    <<SPort:16, DPort:16,
      SeqNo:32,
      AckNo:32,
      Off:4, 0:4, CWR:1, ECE:1, URG:1, ACK:1,
      PSH:1, RST:1, SYN:1, FIN:1, Win:16,
      Sum:16, Urp:16,
      Rest/binary>>
) when Off >= 5 ->
    {Opt, Payload} = options(Off, Rest),
    {#tcp{
        sport = SPort, dport = DPort,
        seqno = SeqNo,
        ackno = AckNo,
        off = Off, cwr = CWR, ece = ECE, urg = URG, ack = ACK,
        psh = PSH, rst = RST, syn = SYN, fin = FIN, win = Win,
        sum = Sum, urp = Urp,
        opt = Opt
    }, Payload};
codec(#tcp{
        sport = SPort, dport = DPort,
        seqno = SeqNo,
        ackno = AckNo,
        off = Off, cwr = CWR, ece = ECE, urg = URG, ack = ACK,
        psh = PSH, rst = RST, syn = SYN, fin = FIN, win = Win,
        sum = Sum, urp = Urp,
        opt = Opt
    }) ->
    Pad = ((Off - 5) * 4 - byte_size(Opt)) * 8,
    <<SPort:16, DPort:16,
      SeqNo:32,
      AckNo:32,
      Off:4, 0:4, CWR:1, ECE:1, URG:1, ACK:1,
      PSH:1, RST:1, SYN:1, FIN:1, Win:16,
      Sum:16, Urp:16,
      Opt/binary, 0:Pad>>.

options(Offset, Binary) ->
    Length = (Offset - 5) * 4,
    <<Options:Length/binary, Payload/binary>> = Binary,
    {Options, Payload}.

%% @doc Used to decoding or encoding the TCP options.
-spec tcp_options(binary()) -> [proplists:property()].
tcp_options(Options) ->
    tcp_options(Options, []).

%% Decoding routines
tcp_options(<<>>, Acc) ->
    lists:reverse(Acc); % Return list of the options in the correct order
%% Kind - 0, End of Option List (RFC 793)
tcp_options(<<0:8, _Rest/binary>>, Acc) ->
    tcp_options(<<>>, [{eol, []} | Acc]);
%% Kind - 1, No-Operation (RFC 793)
tcp_options(<<1:8, Rest/binary>>, Acc) ->
    tcp_options(Rest, [{nop, []} | Acc]);
%% Kind - 2, Length - 4, Maximum Segment Size (RFC 793)
tcp_options(<<2:8, 4:8, MSSValue:16, Rest/binary>>, Acc) ->
    tcp_options(Rest, [{maximum_segment_size, MSSValue} | Acc]);
%% Kind - 3, Length - 3, WSOPT - Window Scale (RFC 1323)
%% Multiplier is calculated as 1 bsl ShiftCount
tcp_options(<<3:8, 3:8, ShiftCount:8, Rest/binary>>, Acc) ->
    tcp_options(Rest, [{window_scale, ShiftCount} | Acc]);
%% Kind - 4, Length - 2, SACK Permitted (RFC 2018)
tcp_options(<<4:8, 2:8, Rest/binary>>, Acc) ->
    tcp_options(Rest, [{sack_permitted, true} | Acc]);
%% Kind - 5, Length - variable, SACK (RFC 2018)
tcp_options(<<5:8, Len:8, Rest/binary>>, Acc) ->
    Length = Len - 2,
    <<Values:Length/binary, Rest1/binary>> = Rest,
    Edges = [{{left_edge, Left}, {right_edge, Right}} || <<Left:32, Right:32>> <= Values],
    tcp_options(Rest1, [{sack, Edges} | Acc]);
%% Kind - 8, Length - 10, TSOPT - Time Stamp Option (RFC 1072, RFC 6247)
tcp_options(<<8:8, 10:8, Timestamp:32, TimestampEchoReply:32, Rest/binary>>, Acc) ->
    tcp_options(Rest, [{tsopt, [{timestamp, Timestamp}, {timestamp_echo_reply, TimestampEchoReply}]} | Acc]);

%% Encoding routines
tcp_options([], Acc) ->
    list_to_binary(lists:reverse(Acc));
tcp_options([{eol, []} | _Rest], Acc) ->
    tcp_options([], [<<0:8>> | Acc]); % No more options after EOL must be
tcp_options([{nop, []} | Rest], Acc) ->
    tcp_options(Rest, [<<1:8>> | Acc]);
tcp_options([{maximum_segment_size, MSSValue} | Rest], Acc) ->
    tcp_options(Rest, [<<2:8, 4:8, MSSValue:16>> | Acc]);
tcp_options([{window_scale, ShiftCount} | Rest], Acc) ->
    tcp_options(Rest, [<<3:8, 3:8, ShiftCount:8>> | Acc]);
tcp_options([{sack_permitted, true} | Rest], Acc) ->
    tcp_options(Rest, [<<4:8, 2:8>> | Acc]);
tcp_options([{sack, Values} | Rest], Acc) ->
    Edges = list_to_binary([<<Left:32, Right:32>> || {{left_edge, Left}, {right_edge, Right}} <- Values]),
    Length = byte_size(Edges) + 2,
    tcp_options(Rest, [<<5:8, Length:8, Edges/binary>> | Acc]);
tcp_options([{tsopt, [{timestamp, Timestamp}, {timestamp_echo_reply, TimestampEchoReply}]} | Rest], Acc) ->
    tcp_options(Rest, [<<8:8, 10:8, Timestamp:32, TimestampEchoReply:32>> | Acc]).
