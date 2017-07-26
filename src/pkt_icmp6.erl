%% Copyright (c) 2009-2017, Michael Santos <michael.santos@gmail.com>
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

-include("pkt_icmp6.hrl").

-export([codec/1]).

%%
%% ICMPv6 Error Messages
%%

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

%%
%% ICMPv6 Informational Messages
%%

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
    <<Type:8, Code:8, Checksum:16, Id:16, Seq:16>>;

%%
%% RFC 4861: Neighbor Discovery for IP version 6 (IPv6)
%%

% Router Solicitation Message
codec(<<?ND_ROUTER_SOLICIT:8, Code:8, Checksum:16, Res:32, Payload/binary>>) ->
    {#icmp6{
        type = ?ND_ROUTER_SOLICIT, code = Code, checksum = Checksum,
        res = Res
    }, Payload};
codec(#icmp6{
        type = ?ND_ROUTER_SOLICIT, code = Code, checksum = Checksum,
        res = Res
    }) ->
    <<?ND_ROUTER_SOLICIT:8, Code:8, Checksum:16, Res:32>>;

% Router Advertisement Message
codec(<<?ND_ROUTER_ADVERT:8, Code:8, Checksum:16, Hop:8, M:1, O:1, Res:6,
        Lifetime:16, Reach:32, Retrans:32, Payload/binary>>) ->
    {#icmp6{
        type = ?ND_ROUTER_ADVERT, code = Code, checksum = Checksum,
        hop = Hop, m = M, o = O, res =Res, lifetime = Lifetime,
        reach = Reach, retrans = Retrans
    }, Payload};
codec(#icmp6{
        type = ?ND_ROUTER_ADVERT, code = Code, checksum = Checksum,
        hop = Hop, m = M, o = O, res =Res, lifetime = Lifetime,
        reach = Reach, retrans = Retrans
    }) ->
    <<?ND_ROUTER_ADVERT:8, Code:8, Checksum:16, Hop:8, M:1, O:1, Res:6,
        Lifetime:16, Reach:32, Retrans:32>>;

% Neighbor Solicitation Message Format
codec(<<?ND_NEIGHBOR_SOLICIT:8, Code:8, Checksum:16, Res:32,
        SA1:16, SA2:16, SA3:16, SA4:16, SA5:16, SA6:16, SA7:16, SA8:16,
        Payload/binary>>) ->
    {#icmp6{
        type = ?ND_NEIGHBOR_SOLICIT, code = Code, checksum = Checksum,
        res = Res,
        saddr = {SA1,SA2,SA3,SA4,SA5,SA6,SA7,SA8}
    }, Payload};
codec(#icmp6{
        type = ?ND_NEIGHBOR_SOLICIT, code = Code, checksum = Checksum,
        res = Res,
        saddr = {SA1,SA2,SA3,SA4,SA5,SA6,SA7,SA8}
    }) ->
    <<?ND_NEIGHBOR_SOLICIT:8, Code:8, Checksum:16, Res:32,
      SA1:16, SA2:16, SA3:16, SA4:16, SA5:16, SA6:16, SA7:16, SA8:16>>;

% Neighbor Advertisement Message
codec(<<?ND_NEIGHBOR_ADVERT:8, Code:8, Checksum:16,
        R:1, S:1, O:1, Res:29,
        SA1:16, SA2:16, SA3:16, SA4:16, SA5:16, SA6:16, SA7:16, SA8:16,
        Payload/binary>>) ->
    {#icmp6{
        type = ?ND_NEIGHBOR_ADVERT, code = Code, checksum = Checksum,
        r = R, s = S, o = O, res = Res,
        saddr = {SA1,SA2,SA3,SA4,SA5,SA6,SA7,SA8}
    }, Payload};
codec(#icmp6{
        type = ?ND_NEIGHBOR_ADVERT, code = Code, checksum = Checksum,
        r = R, s = S, o = O, res = Res,
        saddr = {SA1,SA2,SA3,SA4,SA5,SA6,SA7,SA8}
    }) ->
    <<?ND_NEIGHBOR_ADVERT:8, Code:8, Checksum:16,
      R:1, S:1, O:1, Res:29,
      SA1:16, SA2:16, SA3:16, SA4:16, SA5:16, SA6:16, SA7:16, SA8:16>>;

% Redirect Message
codec(<<?ND_REDIRECT:8, Code:8, Checksum:16,
        Res:32,
        SA1:16, SA2:16, SA3:16, SA4:16, SA5:16, SA6:16, SA7:16, SA8:16,
        DA1:16, DA2:16, DA3:16, DA4:16, DA5:16, DA6:16, DA7:16, DA8:16,
        Payload/binary>>) ->
    {#icmp6{
        type = ?ND_REDIRECT, code = Code, checksum = Checksum,
        res = Res,
        saddr = {SA1,SA2,SA3,SA4,SA5,SA6,SA7,SA8},
        daddr = {DA1,DA2,DA3,DA4,DA5,DA6,DA7,DA8}
    }, Payload};
codec(#icmp6{
        type = ?ND_REDIRECT, code = Code, checksum = Checksum,
        res = Res,
        saddr = {SA1,SA2,SA3,SA4,SA5,SA6,SA7,SA8},
        daddr = {DA1,DA2,DA3,DA4,DA5,DA6,DA7,DA8}
    }) ->
    <<?ND_REDIRECT:8, Code:8, Checksum:16,
       Res:32,
       SA1:16, SA2:16, SA3:16, SA4:16, SA5:16, SA6:16, SA7:16, SA8:16,
       DA1:16, DA2:16, DA3:16, DA4:16, DA5:16, DA6:16, DA7:16, DA8:16>>;

%%
%% RFC 2710: Multicast Listener Discovery (MLD) for IPv6
%% RFC 4604: Multicast Listener Discovery Version 2 (MLDv2) for IPv6
%%
codec(<<Type:8, Code:8, Checksum:16,
        Delay:16, Res:16,
        DA1:16, DA2:16, DA3:16, DA4:16, DA5:16, DA6:16, DA7:16, DA8:16,
        Payload/binary>>) when
        Type =:= ?MLD_LISTENER_QUERY;
        Type =:= ?MLD_LISTENER_REPORT;
        Type =:= ?MLD_LISTENER_REDUCTION ->
    {#icmp6{
        type = Type, code = Code, checksum = Checksum,
        delay = Delay, res = Res,
        daddr = {DA1,DA2,DA3,DA4,DA5,DA6,DA7,DA8}
    }, Payload};
codec(#icmp6{
        type = Type, code = Code, checksum = Checksum,
        delay = Delay, res = Res,
        daddr = {DA1,DA2,DA3,DA4,DA5,DA6,DA7,DA8}
    }) when
        Type =:= ?MLD_LISTENER_QUERY;
        Type =:= ?MLD_LISTENER_REPORT;
        Type =:= ?MLD_LISTENER_REDUCTION ->
    <<Type:8, Code:8, Checksum:16,
       Delay:16, Res:16,
       DA1:16, DA2:16, DA3:16, DA4:16, DA5:16, DA6:16, DA7:16, DA8:16>>;

codec(<<?MLD_LISTENER_REPORTV2:8, Res:8, Checksum:16,
        Res2:16, M:16, Payload/binary>>) ->
    {#icmp6{
        type = ?MLD_LISTENER_REPORTV2, res = Res, checksum = Checksum,
        res2 = Res2, m = M
    }, Payload};
codec(#icmp6{
        type = ?MLD_LISTENER_REPORTV2, res = Res, checksum = Checksum,
        res2 = Res2, m = M
    }) ->
    <<?MLD_LISTENER_REPORTV2:8, Res:8, Checksum:16,
        Res2:16, M:16>>.
