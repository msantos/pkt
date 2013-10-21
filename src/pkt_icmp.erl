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
-module(pkt_icmp).

-include("pkt_icmp.hrl").

-export([codec/1]).

% Destination Unreachable Message
codec(<<?ICMP_DEST_UNREACH:8, Code:8, Checksum:16, Unused:32/bits, Payload/binary>>) ->
    {#icmp{
        type = ?ICMP_DEST_UNREACH, code = Code, checksum = Checksum, un = Unused
    }, Payload};
codec(#icmp{
        type = ?ICMP_DEST_UNREACH, code = Code, checksum = Checksum, un = Unused
    }) ->
    <<?ICMP_DEST_UNREACH:8, Code:8, Checksum:16, Unused:32/bits>>;

% Time Exceeded Message
codec(<<?ICMP_TIME_EXCEEDED:8, Code:8, Checksum:16, Unused:32/bits, Payload/binary>>) ->
    {#icmp{
        type = ?ICMP_TIME_EXCEEDED, code = Code, checksum = Checksum, un = Unused
    }, Payload};
codec(#icmp{
        type = ?ICMP_TIME_EXCEEDED, code = Code, checksum = Checksum, un = Unused
    }) ->
    <<?ICMP_TIME_EXCEEDED:8, Code:8, Checksum:16, Unused:32/bits>>;

% Parameter Problem Message
codec(<<?ICMP_PARAMETERPROB:8, Code:8, Checksum:16, Pointer:8, Unused:24/bits, Payload/binary>>) ->
    {#icmp{
        type = ?ICMP_PARAMETERPROB, code = Code, checksum = Checksum, pointer = Pointer,
        un = Unused
    }, Payload};
codec(#icmp{
        type = ?ICMP_PARAMETERPROB, code = Code, checksum = Checksum, pointer = Pointer,
        un = Unused
    }) ->
    <<?ICMP_PARAMETERPROB:8, Code:8, Checksum:16, Pointer:8, Unused:24/bits>>;

% Source Quench Message
codec(<<?ICMP_SOURCE_QUENCH:8, 0:8, Checksum:16, Unused:32/bits, Payload/binary>>) ->
    {#icmp{
        type = ?ICMP_SOURCE_QUENCH, code = 0, checksum = Checksum, un = Unused
    }, Payload};
codec(#icmp{
        type = ?ICMP_SOURCE_QUENCH, code = Code, checksum = Checksum, un = Unused
    }) ->
    <<?ICMP_SOURCE_QUENCH:8, Code:8, Checksum:16, Unused:32/bits>>;

% Redirect Message
codec(<<?ICMP_REDIRECT:8, Code:8, Checksum:16, DA1, DA2, DA3, DA4, Payload/binary>>) ->
    {#icmp{
        type = ?ICMP_REDIRECT, code = Code, checksum = Checksum, gateway = {DA1,DA2,DA3,DA4}
    }, Payload};
codec(#icmp{
        type = ?ICMP_REDIRECT, code = Code, checksum = Checksum, gateway = {DA1,DA2,DA3,DA4}
    }) ->
    <<?ICMP_REDIRECT:8, Code:8, Checksum:16, DA1, DA2, DA3, DA4>>;

% Echo or Echo Reply Message
codec(<<Type:8, Code:8, Checksum:16, Id:16, Sequence:16, Payload/binary>>)
when Type =:= ?ICMP_ECHO; Type =:= ?ICMP_ECHOREPLY ->
    {#icmp{
        type = Type, code = Code, checksum = Checksum, id = Id,
        sequence = Sequence
    }, Payload};
codec(#icmp{
        type = Type, code = Code, checksum = Checksum, id = Id,
        sequence = Sequence
    })
when Type =:= ?ICMP_ECHO; Type =:= ?ICMP_ECHOREPLY ->
    <<Type:8, Code:8, Checksum:16, Id:16, Sequence:16>>;

% Timestamp or Timestamp Reply Message
codec(<<Type:8, 0:8, Checksum:16, Id:16, Sequence:16, TS_Orig:32, TS_Recv:32, TS_Tx:32>>)
when Type =:= ?ICMP_TIMESTAMP; Type =:= ?ICMP_TIMESTAMPREPLY ->
    {#icmp{
        type = Type, code = 0, checksum = Checksum, id = Id,
        sequence = Sequence, ts_orig = TS_Orig, ts_recv = TS_Recv, ts_tx = TS_Tx
    }, <<>>};
codec(#icmp{
        type = Type, code = Code, checksum = Checksum, id = Id,
        sequence = Sequence, ts_orig = TS_Orig, ts_recv = TS_Recv, ts_tx = TS_Tx
    }) when Type =:= ?ICMP_TIMESTAMP; Type =:= ?ICMP_TIMESTAMPREPLY ->
    <<Type:8, Code:8, Checksum:16, Id:16, Sequence:16, TS_Orig:32, TS_Recv:32, TS_Tx:32>>;

% Information Request or Information Reply Message
codec(<<Type:8, 0:8, Checksum:16, Id:16, Sequence:16>>)
when Type =:= ?ICMP_INFO_REQUEST; Type =:= ?ICMP_INFO_REPLY ->
    {#icmp{
        type = Type, code = 0, checksum = Checksum, id = Id,
        sequence = Sequence
    }, <<>>};
codec(#icmp{
        type = Type, code = Code, checksum = Checksum, id = Id,
        sequence = Sequence
    }) when Type =:= ?ICMP_INFO_REQUEST; Type =:= ?ICMP_INFO_REPLY ->
    <<Type:8, Code:8, Checksum:16, Id:16, Sequence:16>>;

% Catch/build arbitrary types
codec(<<Type:8, Code:8, Checksum:16, Un:32, Payload/binary>>) ->
    {#icmp{
        type = Type, code = Code, checksum = Checksum, un = Un
    }, Payload};
codec(#icmp{type = Type, code = Code, checksum = Checksum, un = Un}) ->
    <<Type:8, Code:8, Checksum:16, Un:32>>.
