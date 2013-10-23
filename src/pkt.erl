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
-module(pkt).

-include("pkt.hrl").

-define(ETHERHDRLEN, 16).
-define(IPV4HDRLEN, 20).
-define(IPV6HDRLEN, 40).
-define(TCPHDRLEN, 20).
-define(UDPHDRLEN, 8).
-define(ICMPHDRLEN, 8).
-define(ICMP6HDRLEN, 8).
-define(GREHDRLEN, 4).

-export([
        checksum/1,
        decapsulate/1, decapsulate/2,
        decode/1, decode/2,
        makesum/1,
        ether/1,
        ether_type/1,
        arp/1,
        null/1,
        linux_cooked/1,
        icmp/1,
        icmp6/1,
        ipv4/1,
        ipv6/1,
        ipproto/1, proto/1,
        tcp/1,
        tcp_options/1,
        udp/1,
        sctp/1,
        dlt/1, link_type/1
]).

decapsulate(DLT, Data) ->
    decapsulate({DLT, Data}).

decapsulate({DLT, Data}) when is_integer(DLT) ->
    decapsulate_next({link_type(DLT), Data}, []);
decapsulate({DLT, Data}) when is_atom(DLT) ->
    decapsulate_next({DLT, Data}, []);
decapsulate(Data) when is_binary(Data) ->
    decapsulate_next({en10mb, Data}, []).

decapsulate_next({null, Data}, Packet) when byte_size(Data) >= 16 ->
    {Hdr, Payload} = null(Data),
    decapsulate_next({next(Hdr), Payload}, [Hdr|Packet]);
decapsulate_next({linux_sll, Data}, Packet) when byte_size(Data) >= 16 ->
    {Hdr, Payload} = linux_cooked(Data),
    decapsulate_next({next(Hdr), Payload}, [Hdr|Packet]);
decapsulate_next({en10mb, Data}, Packet) when byte_size(Data) >= ?ETHERHDRLEN ->
    {Hdr, Payload} = ether(Data),
    decapsulate_next({next(Hdr), Payload}, [Hdr|Packet]);

decapsulate_next({ipv4, Data}, Packet) when byte_size(Data) >= ?IPV4HDRLEN ->
    {Hdr, Payload} = ipv4(Data),
    decapsulate_next({next(Hdr), Payload}, [Hdr|Packet]);
decapsulate_next({ipv6, Data}, Packet) when byte_size(Data) >= ?IPV6HDRLEN ->
    {Hdr, Payload} = ipv6(Data),
    decapsulate_next({next(Hdr), Payload}, [Hdr|Packet]);
decapsulate_next({gre, Data}, Packet) when byte_size(Data) >= ?GREHDRLEN ->
    {Hdr, Payload} = gre(Data),
    decapsulate_next({next(Hdr), Payload}, [Hdr|Packet]);

decapsulate_next({arp, Data}, Packet) when byte_size(Data) >= 28 ->
    {Hdr, Payload} = arp(Data),
    lists:reverse([Payload, Hdr|Packet]);
decapsulate_next({tcp, Data}, Packet) when byte_size(Data) >= ?TCPHDRLEN ->
    {Hdr, Payload} = tcp(Data),
    lists:reverse([Payload, Hdr|Packet]);
decapsulate_next({udp, Data}, Packet) when byte_size(Data) >= ?UDPHDRLEN ->
    {Hdr, Payload} = udp(Data),
    lists:reverse([Payload, Hdr|Packet]);
decapsulate_next({sctp, Data}, Packet) when byte_size(Data) >= 12 ->
    {Hdr, Payload} = sctp(Data),
    lists:reverse([Payload, Hdr|Packet]);
decapsulate_next({icmp, Data}, Packet) when byte_size(Data) >= ?ICMPHDRLEN ->
    {Hdr, Payload} = icmp(Data),
    lists:reverse([Payload, Hdr|Packet]);
decapsulate_next({icmp6, Data}, Packet) when byte_size(Data) >= ?ICMP6HDRLEN ->
    {Hdr, Payload} = icmp6(Data),
    lists:reverse([Payload, Hdr|Packet]);
decapsulate_next({_, Data}, Packet) ->
    lists:reverse([{truncated, Data}|Packet]).

decode(Data) when is_binary(Data) ->
    decode(en10mb, Data).

decode(Proto, Data) when is_atom(Proto) ->
    try decode_next({Proto, Data}, []) of
        N ->
            N
    catch
        error:_ ->
            {error, [], {unsupported, Data}}
    end.

% Aliases
decode_next({en10mb, Data}, Packet) ->
    decode_next({ether, Data}, Packet);
decode_next({linux_sll, Data}, Packet) ->
    decode_next({linux_cooked, Data}, Packet);

% Protocols pointing to next header
decode_next({Proto, Data}, Packet) when
    Proto =:= ether;
    Proto =:= gre;
    Proto =:= ipv4;
    Proto =:= ipv6;
    Proto =:= linux_cooked;
    Proto =:= null ->
    try_decode_next(Proto, Data, Packet);

% Data follows header
decode_next({Proto, Data}, Packet) when
    Proto =:= arp;
    Proto =:= icmp;
    Proto =:= icmp6;
    Proto =:= sctp;
    Proto =:= sctp;
    Proto =:= tcp;
    Proto =:= udp ->
    try_decode(Proto, Data, Packet).

try_decode_next(Fun, Data, Packet) ->
    Decode = try ?MODULE:Fun(Data) of
        N ->
            {ok, N}
    catch
        error:_ ->
            {error, lists:reverse(Packet), {Fun, Data}}
    end,

    case Decode of
        {ok, {Header, Payload}} ->
            case next(Header) of
                unsupported ->
                    {error, lists:reverse([Header|Packet]), {unsupported, Payload}};
                Type ->
                    decode_next({Type, Payload}, [Header|Packet])
            end;
        {error, _, _} = Error ->
            Error
    end.

try_decode(Fun, Data, Packet) ->
    try ?MODULE:Fun(Data) of
        {Header, Payload} ->
            {ok, lists:reverse([Payload, Header|Packet])}
    catch
        error:_ ->
            {error, lists:reverse(Packet), {Fun, Data}}
    end.

next(#null{family = Family}) -> family(Family);
next(#linux_cooked{pro = Pro}) -> ether_type(Pro);
next(#ether{type = Type}) -> ether_type(Type);
next(#ipv4{p = P}) -> ipproto(P);
next(#ipv6{next = Next}) -> ipproto(Next);
next(#gre{type = Type}) -> ether_type(Type).

%% BSD loopback
null(N) ->
    pkt_null:codec(N).

%% Linux cooked capture ("-i any") - DLT_LINUX_SLL
linux_cooked(N) ->
    pkt_linux_cooked:codec(N).

%% Ethernet
ether(N) ->
    pkt_ether:codec(N).

ether_type(N) ->
    pkt_ether:type(N).


%% ARP
arp(N) ->
    pkt_arp:codec(N).

%% IPv4
ipv4(N) ->
    pkt_ipv4:codec(N).


%% IPv6
ipv6(N) ->
    pkt_ipv6:codec(N).

%% GRE
gre(N) ->
    pkt_gre:codec(N).

%% TCP
tcp(N) ->
    pkt_tcp:codec(N).

tcp_options(N) ->
    pkt_tcp:options(N).

%% SCTP
sctp(N) ->
    pkt_sctp:codec(N).

%% UDP
udp(N) ->
    pkt_udp:codec(N).

%% ICMP
icmp(N) ->
    pkt_icmp:codec(N).

%% ICMPv6
icmp6(N) ->
    pkt_icmp6:codec(N).

%% Datalink types
link_type(N) ->
    dlt(N).

dlt(N) ->
    pkt_dlt:codec(N).

%% IP protocols
proto(N) ->
    ipproto(N).

ipproto(N) ->
    pkt_ipproto:codec(N).

%% Protocol families
family(?PF_INET) -> ipv4;
family(?PF_INET6) -> ipv6;
family(_) -> unsupported.

%%
%% Utility functions
%%

% TCP pseudoheader checksum
checksum([#ipv4{
        saddr = {SA1,SA2,SA3,SA4},
        daddr = {DA1,DA2,DA3,DA4},
        len = IPLen,
        hl = HL
    },
    #tcp{
        off = Off
    } = TCPhdr,
    Payload
]) ->
    Len = IPLen - (HL * 4),
    PayloadLen = IPLen - ((HL * 4) + (Off * 4)),
    Pad = case Len rem 2 of
        0 -> 0;
        1 -> 8
    end,
    TCP = tcp(TCPhdr),
    checksum(
        <<SA1,SA2,SA3,SA4,
          DA1,DA2,DA3,DA4,
          0:8,
          ?IPPROTO_TCP:8,
          Len:16,
          TCP/binary,
          Payload:PayloadLen/binary,
          0:Pad>>
    );

% UDP pseudoheader checksum
checksum([#ipv4{
        saddr = {SA1,SA2,SA3,SA4},
        daddr = {DA1,DA2,DA3,DA4}
    },
    #udp{
        ulen = Len
    } = Hdr,
    Payload
]) ->
    UDP = udp(Hdr),
    Pad = case Len rem 2 of
        0 -> 0;
        1 -> 8
    end,
    checksum(
        <<SA1,SA2,SA3,SA4,
          DA1,DA2,DA3,DA4,
          0:8,
          ?IPPROTO_UDP:8,
          Len:16,
          UDP/binary,
          Payload/bits,
          0:Pad>>
    );

checksum(#ipv4{} = H) ->
    checksum(ipv4(H));
checksum(Hdr) ->
    lists:foldl(fun compl/2, 0, [ W || <<W:16>> <= Hdr ]).

makesum(Hdr) -> 16#FFFF - checksum(Hdr).

compl(N) when N =< 16#FFFF -> N;
compl(N) -> (N band 16#FFFF) + (N bsr 16).
compl(N,S) -> compl(N+S).
