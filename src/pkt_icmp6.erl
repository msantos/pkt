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
-module(pkt_icmp6).

-include("pkt.hrl").

-export([codec/1]).

% ICMPv6 Error Messages

% Destination Unreachable Message
codec(<<?ICMP6_DST_UNREACH:8, Code:8, Checksum:16, Unused:32/bits, Payload/binary>>) ->
    {#icmp6{
        type = ?ICMP6_DST_UNREACH, code = Code, checksum = Checksum, un = Unused
    }, Payload};
codec(#icmp6{
        type = ?ICMP6_DST_UNREACH, code = Code, checksum = Checksum, un = Unused
    }) ->
    <<?ICMP6_DST_UNREACH:8, Code:8, Checksum:16, Unused:32/bits>>;

% Packet too big
codec(<<?ICMP6_PACKET_TOO_BIG:8, Code:8, Checksum:16, MTU:32, Payload/binary>>) ->
    {#icmp6{
        type = ?ICMP6_PACKET_TOO_BIG, code = Code, checksum = Checksum, mtu = MTU
    }, Payload};
codec(#icmp6{
        type = ?ICMP6_PACKET_TOO_BIG, code = Code, checksum = Checksum, mtu = MTU
    }) ->
    <<?ICMP6_PACKET_TOO_BIG:8, Code:8, Checksum:16, MTU:32>>;

% Time Exceeded Message
codec(<<?ICMP6_TIME_EXCEEDED:8, Code:8, Checksum:16, Unused:32/bits, Payload/binary>>) ->
    {#icmp6{
        type = ?ICMP6_TIME_EXCEEDED, code = Code, checksum = Checksum, un = Unused
    }, Payload};
codec(#icmp6{
        type = ?ICMP6_TIME_EXCEEDED, code = Code, checksum = Checksum, un = Unused
    }) ->
    <<?ICMP6_TIME_EXCEEDED:8, Code:8, Checksum:16, Unused:32/bits>>;

% Parameter Problem Message
codec(<<?ICMP6_PARAM_PROB:8, Code:8, Checksum:16, Ptr:32, Payload/binary>>) ->
    {#icmp6{
        type = ?ICMP6_PARAM_PROB, code = Code, checksum = Checksum, pptr = Ptr
    }, Payload};
codec(#icmp6{
        type = ?ICMP6_PARAM_PROB, code = Code, checksum = Checksum, pptr = Ptr
    }) ->
    <<?ICMP6_PARAM_PROB:8, Code:8, Checksum:16, Ptr:32>>;

% ICMPv6 Informational Messages

% Echo Request Message/Echo Reply Message
codec(<<Type:8, Code:8, Checksum:16, Id:16, Seq:16, Payload/binary>>)
        when Type =:= ?ICMP6_ECHO_REQUEST; Type =:= ?ICMP6_ECHO_REPLY ->
    {#icmp6{
        type = Type, code = Code, checksum = Checksum,
        id = Id, seq = Seq
    }, Payload};
codec(#icmp6{
        type = Type, code = Code, checksum = Checksum,
        id = Id, seq = Seq
    }) when Type =:= ?ICMP6_ECHO_REQUEST; Type =:= ?ICMP6_ECHO_REPLY ->
    <<Type:8, Code:8, Checksum:16, Id:16, Seq:16>>.
