%% Copyright (c) 2009-2015, Michael Santos <michael.santos@gmail.com>
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

-export([
        checksum/1,
        build_checksum/1,
        decapsulate/1, decapsulate/2,
        decode/1, decode/2,
        makesum/1,
        ether/1,
        ether_type/1,
        mpls/1,
        '802.1q'/1,
        llc/1,
        arp/1,
        lldp/1,
        null/1,
        gre/1,
        linux_cooked/1,
        icmp/1,
        icmp6/1,
        igmp/1,
        ipv4/1,
        ipv6/1,
        vrrp/1,
        ipv6_ah/1,
        ipv6_dstopts/1,
        ipv6_esp/1,
        ipv6_fragment/1,
        ipv6_hopopts/1,
        ipv6_routing/1,
        ipproto/1, proto/1,
        tcp/1,
        tcp_options/1,
        udp/1,
        sctp/1,
        verify_checksum/1,
        dlt/1, link_type/1
]).

-type bit() :: 0 .. 1.
-type in_port_t() :: 0 .. 16#ffff.
-type bit4() :: 0 .. 2#1111.
-type uint8_t() :: 0..16#ff.
-type uint16_t() :: 0 .. 16#ffff.
-type uint32_t() :: 0 .. 16#ffffffff.
-type in_addr() :: {uint8_t(),uint8_t(),uint8_t(),uint8_t()}.
-type in6_addr() :: {uint16_t(),uint16_t(),uint16_t(),uint16_t(),uint16_t(),uint16_t(),uint16_t(),uint16_t()}.

-export_type([
        bit/0,
        in6_addr/0,
        in_addr/0,
        in_port_t/0,
        bit4/0,
        uint8_t/0,
        uint16_t/0,
        uint32_t/0
    ]).

% For integers, assume a whole frame and check the datalink type.
%
% Atoms can indicate any protocol type.
decapsulate(Proto, Data) ->
    decapsulate({Proto, Data}).

decapsulate({DLT, Data}) when is_integer(DLT) ->
    decapsulate_next({dlt(DLT), Data}, []);
decapsulate({Proto, Data}) when is_atom(Proto) ->
    decapsulate_next({Proto, Data}, []);
decapsulate(Data) when is_binary(Data) ->
    decapsulate_next({ether, Data}, []).

% Aliases
decapsulate_next({en10mb, Data}, Headers) ->
    decapsulate_next({ether, Data}, Headers);
decapsulate_next({linux_sll, Data}, Headers) ->
    decapsulate_next({linux_cooked, Data}, Headers);

% Protocol header indicates next header
decapsulate_next({null, Data}, Headers) ->
    {Header, Payload} = null(Data),
    decapsulate_next({next(Header), Payload}, [Header|Headers]);
decapsulate_next({linux_cooked, Data}, Headers) ->
    {Header, Payload} = linux_cooked(Data),
    decapsulate_next({next(Header), Payload}, [Header|Headers]);
decapsulate_next({ether, Data}, Headers) ->
    {Header, Payload} = ether(Data),
    decapsulate_next({next(Header), Payload}, [Header|Headers]);
decapsulate_next({mpls, Data}, Headers) ->
    {Header, Next, Payload} = mpls(Data),
    decapsulate_next({Next, Payload}, [Header|Headers]);
decapsulate_next({'802.1q', Data}, Headers) ->
    {Header, Payload} = '802.1q'(Data),
    decapsulate_next({next(Header), Payload}, [Header|Headers]);
decapsulate_next({'802.1qinq', Data}, Headers) ->
    {Header, Payload} = '802.1q'(Data),
    decapsulate_next({next(Header), Payload}, [Header|Headers]);
decapsulate_next({llc, Data}, Headers) ->
    {Header, Payload} = llc(Data),
    lists:reverse([Payload, Header|Headers]);

decapsulate_next({ipv4, Data}, Headers) ->
    {Header, Payload} = ipv4(Data),
    decapsulate_next({next(Header), Payload}, [Header|Headers]);
decapsulate_next({ipv6, Data}, Headers) ->
    {Header, Payload} = ipv6(Data),
    decapsulate_next({next(Header), Payload}, [Header|Headers]);

decapsulate_next({ipv6_ah, Data}, Headers) ->
    {Header, Payload} = ipv6_ah(Data),
    decapsulate_next({next(Header), Payload}, [Header|Headers]);
decapsulate_next({ipv6_dstopts, Data}, Headers) ->
    {Header, Payload} = ipv6_dstopts(Data),
    decapsulate_next({next(Header), Payload}, [Header|Headers]);
decapsulate_next({ipv6_esp, Data}, Headers) ->
    {Header, Payload} = ipv6_esp(Data),
    decapsulate_next({next(Header), Payload}, [Header|Headers]);
decapsulate_next({ipv6_fragment, Data}, Headers) ->
    {Header, Payload} = ipv6_fragment(Data),
    decapsulate_next({next(Header), Payload}, [Header|Headers]);
decapsulate_next({ipv6_hopopts, Data}, Headers) ->
    {Header, Payload} = ipv6_hopopts(Data),
    decapsulate_next({next(Header), Payload}, [Header|Headers]);
decapsulate_next({ipv6_routing, Data}, Headers) ->
    {Header, Payload} = ipv6_routing(Data),
    decapsulate_next({next(Header), Payload}, [Header|Headers]);

decapsulate_next({gre, Data}, Headers) ->
    {Header, Payload} = gre(Data),
    decapsulate_next({next(Header), Payload}, [Header|Headers]);

% Upper layer: data follows header
decapsulate_next({arp, Data}, Headers) ->
    {Header, Payload} = arp(Data),
    lists:reverse([Payload, Header|Headers]);
decapsulate_next({lldp, Data}, Headers) ->
    {Header, Payload} = lldp(Data),
    lists:reverse([Payload, Header|Headers]);
decapsulate_next({tcp, Data}, Headers) ->
    {Header, Payload} = tcp(Data),
    lists:reverse([Payload, Header|Headers]);
decapsulate_next({udp, Data}, Headers) ->
    {Header, Payload} = udp(Data),
    lists:reverse([Payload, Header|Headers]);
decapsulate_next({sctp, Data}, Headers) ->
    {Header, Payload} = sctp(Data),
    lists:reverse([Payload, Header|Headers]);
decapsulate_next({icmp, Data}, Headers) ->
    {Header, Payload} = icmp(Data),
    lists:reverse([Payload, Header|Headers]);
decapsulate_next({icmp6, Data}, Headers) ->
    {Header, Payload} = icmp6(Data),
    lists:reverse([Payload, Header|Headers]);
decapsulate_next({igmp, Data}, Headers) ->
    {Header, Payload} = igmp(Data),
    lists:reverse([Payload, Header|Headers]);
decapsulate_next({vrrp, Data}, Headers) ->
    {Header, Payload} = vrrp(Data),
    lists:reverse([Payload, Header | Headers]);
% IPv6 NONE pseudo-header
decapsulate_next({ipv6_none, Data}, Headers) ->
    lists:reverse([Data|Headers]).

decode(Data) when is_binary(Data) ->
    decode(ether, Data).

decode(Proto, Data) when is_atom(Proto) ->
    try decode_next({Proto, Data}, []) of
        N ->
            N
    catch
        error:_ ->
            {error, [], {unsupported, Data}}
    end.

% Aliases
decode_next({en10mb, Data}, Headers) ->
    decode_next({ether, Data}, Headers);
decode_next({linux_sll, Data}, Headers) ->
    decode_next({linux_cooked, Data}, Headers);

% Protocol header indicates next header
decode_next({Proto, Data}, Headers) when
    Proto =:= ether;
    Proto =:= gre;
    Proto =:= ipv4;
    Proto =:= ipv6;
    Proto =:= linux_cooked;
    Proto =:= null;

    Proto =:= ipv6_ah;
    Proto =:= ipv6_dstopts;
    Proto =:= ipv6_esp;
    Proto =:= ipv6_fragment;
    Proto =:= ipv6_hopopts;
    Proto =:= ipv6_routing ->

    Decode = try ?MODULE:Proto(Data) of
        N ->
            {ok, N}
    catch
        error:_ ->
            {error, lists:reverse(Headers), {Proto, Data}}
    end,

    case Decode of
        {ok, {Header, Payload}} ->
            try next(Header) of
                Next ->
                    decode_next({Next, Payload}, [Header|Headers])
            catch
                error:_ ->
                    {error, lists:reverse([Header|Headers]), {unsupported, Payload}}
            end;
        {error, _, _} = Error ->
            Error
    end;

% Upper layer: data follows header

% IPv6 NONE pseudo-header
decode_next({ipv6_none, Data}, Headers) ->
    {ok, {lists:reverse(Headers), Data}};

decode_next({Proto, Data}, Headers) when
    Proto =:= arp;
    Proto =:= icmp;
    Proto =:= icmp6;
    Proto =:= igmp;
    Proto =:= sctp;
    Proto =:= sctp;
    Proto =:= tcp;
    Proto =:= udp ->
    try ?MODULE:Proto(Data) of
        {Header, Payload} ->
            {ok, {lists:reverse([Header|Headers]), Payload}}
    catch
        error:_ ->
            {error, lists:reverse(Headers), {Proto, Data}}
    end.

next(#null{family = Family}) -> family(Family);
next(#linux_cooked{pro = Pro}) -> ether_type(Pro);
next(#ether{type = Type}) -> ether_type(Type);
next(#'802.1q'{type = Type}) -> ether_type(Type);
next(#ipv4{p = P}) -> ipproto(P);
next(#gre{type = Type}) -> ether_type(Type);
next(#ipv6{next = Next}) -> ipproto(Next);
next(#ipv6_ah{next = Next}) -> ipproto(Next);
next(#ipv6_dstopts{next = Next}) -> ipproto(Next);
next(#ipv6_esp{next = Next}) -> ipproto(Next);
next(#ipv6_fragment{next = Next}) -> ipproto(Next);
next(#ipv6_hopopts{next = Next}) -> ipproto(Next);
next(#ipv6_routing{next = Next}) -> ipproto(Next).

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

%% MPLS
mpls(N) ->
    pkt_mpls:codec(N).

%% ARP
arp(N) ->
    pkt_arp:codec(N).

%% LLDP
lldp(N) ->
    pkt_lldp:codec(N).

llc(N) ->
    pkt_llc:codec(N).

'802.1q'(N) ->
    pkt_802_1q:codec(N).

%% IPv4
ipv4(N) ->
    pkt_ipv4:codec(N).


%% IPv6
ipv6(N) ->
    pkt_ipv6:codec(N).

ipv6_ah(N) ->
    pkt_ipv6_ah:codec(N).
ipv6_dstopts(N) ->
    pkt_ipv6_dstopts:codec(N).
ipv6_esp(N) ->
    pkt_ipv6_esp:codec(N).
ipv6_fragment(N) ->
    pkt_ipv6_fragment:codec(N).
ipv6_hopopts(N) ->
    pkt_ipv6_hopopts:codec(N).
ipv6_routing(N) ->
    pkt_ipv6_routing:codec(N).

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

%% IGMP
igmp(N) ->
    pkt_igmp:codec(N).

vrrp(N) ->
    pkt_vrrp:codec(N).

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

%% Protocol families: BSD NULL (loopback) linktype
family(?PF_INET) -> ipv4;
family(Family) ->
    case {os:type(), Family} of
        {{unix,darwin}, 30} -> ipv6;
        {{unix,freebsd}, 28} -> ipv6;
        {{unix,netbsd}, 24} -> ipv6;
        {{unix,openbsd}, 24} -> ipv6
    end.

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
    TCP = tcp(TCPhdr),
    checksum(
        <<SA1,SA2,SA3,SA4,
          DA1,DA2,DA3,DA4,
          0:8,
          ?IPPROTO_TCP:8,
          Len:16,
          TCP/binary,
          Payload:PayloadLen/binary>>
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
    checksum(
        <<SA1,SA2,SA3,SA4,
          DA1,DA2,DA3,DA4,
          0:8,
          ?IPPROTO_UDP:8,
          Len:16,
          UDP/binary,
          Payload/bits>>
    );

checksum(#ipv4{} = H) ->
    checksum(ipv4(H));

checksum([#ipv6{
	     len = IPLen, next = Next,
	     saddr = {SA1, SA2, SA3, SA4, SA5, SA6, SA7, SA8},
	     daddr = {DA1, DA2, DA3, DA4, DA5, DA6, DA7, DA8}
	    },
	    #tcp{
                 off = Off
            } = TCPhdr,
	  Payload
	 ]) when Next == ?IPPROTO_TCP ->
    PayloadLen = IPLen - (Off * 4),
    %% calculation of the TCP header
    TCP_Header = pkt:tcp(TCPhdr),
    pkt:checksum(
      <<
        %% calculation of the ipv6 pseudo header: rfc2460
	SA1:16, SA2:16, SA3:16, SA4:16, SA5:16, SA6:16, SA7:16, SA8:16,
	DA1:16, DA2:16, DA3:16, DA4:16, DA5:16, DA6:16, DA7:16, DA8:16,
        IPLen:32,
        0:24, Next:8,
        TCP_Header/binary,
        %% calculation of the padded payload
	Payload:PayloadLen/binary>>
     );

checksum([#ipv6{
	     len = IPLen, next = Next,
	     saddr = {SA1, SA2, SA3, SA4, SA5, SA6, SA7, SA8},
	     daddr = {DA1, DA2, DA3, DA4, DA5, DA6, DA7, DA8}
	    },
	    #udp{
            } = UDPhdr,
	  Payload
	 ]) when Next == ?IPPROTO_UDP ->
    PayloadLen = IPLen - 8, % header offset for saddr, daddr is 8
    %% calculation of the UDP header
    UDP_Header = pkt:udp(UDPhdr),
    pkt:checksum(
      <<
        %% calculation of the ipv6 pseudo header: rfc2460
	SA1:16, SA2:16, SA3:16, SA4:16, SA5:16, SA6:16, SA7:16, SA8:16,
	DA1:16, DA2:16, DA3:16, DA4:16, DA5:16, DA6:16, DA7:16, DA8:16,
        IPLen:32,
        0:24, Next:8,
        UDP_Header/binary,
        %% calculation of the padded payload
	Payload:PayloadLen/binary>>
     );

checksum(#ipv6{} = H) ->
    checksum(ipv6(H));

checksum(Bin) ->
 	checksum(Bin, 0).

checksum(<<N1:64/integer, N2:64/integer, N3:64/integer, N4:64/integer, N5:64/integer, N6:64/integer, N7:64/integer, N8:64/integer, ReminderBin/binary>>, Checksum128Bit) ->
 	checksum(ReminderBin, N1+N2+N3+N4+N5+N6+N7+N8+Checksum128Bit);

checksum(<<N1:64/integer, N2:64/integer, N3:64/integer, N4:64/integer, ReminderBin/binary>>, Checksum128Bit) ->
 	checksum(ReminderBin, N1+N2+N3+N4+Checksum128Bit);

checksum(<<N1:64/integer, N2:64/integer, ReminderBin/binary>>, Checksum128Bit) ->
 	checksum(ReminderBin, N1+N2+Checksum128Bit);

checksum(<<N:64/integer, ReminderBin/binary>>, Checksum128Bit) ->
 	checksum(ReminderBin, N+Checksum128Bit);

checksum(<<N:16/integer, ReminderBin/binary>>, Checksum128Bit) ->
 	checksum(ReminderBin, N+Checksum128Bit);

checksum(<<N:8/integer>>, Checksum128Bit) ->
 	checksum(<<>>, (N bsl 8)+Checksum128Bit);

checksum(<<>>, Checksum128Bit) ->
        Checksum64Bit = foldWithOverflow64(Checksum128Bit),
        Checksum32Bit = foldWithOverflow32(Checksum64Bit),
        Checksum16Bit = foldWithOverflow16(Checksum32Bit),
        Checksum16Bit.

foldWithOverflow64(A) ->
        C = A band 16#FFFFFFFFFFFFFFFF,
	D = (A bsr 64) band 16#FFFFFFFFFFFFFFFF,
	E = (C + D) band 16#FFFFFFFFFFFFFFFF,
        case E < D of
		true ->
			E + 1; % overflow
		false ->
			E
         end.

foldWithOverflow32(A) ->
        C = A band 16#FFFFFFFF,
	D = (A bsr 32) band 16#FFFFFFFF,
	E = (C + D) band 16#FFFFFFFF,
        case E < D of
		true ->
			E + 1; % overflow
		false ->
			E
         end.

foldWithOverflow16(A) ->
        C = A band 16#FFFF,
	D = (A bsr 16) band 16#FFFF,
	E = (C + D) band 16#FFFF,
        case E < D of
		true ->
			E + 1; % overflow
		false ->
			E
         end.


makesum([IP, UDP, Payload]) when % handle UDP packets
    (is_record(IP,ipv4) or is_record(IP,ipv6)) and is_record(UDP,udp)->
    Sum = (checksum([IP, UDP, Payload]) bxor 16#FFFF) band 16#FFFF, % bitwise-complement
    if
      Sum == 0 -> 16#FFFF; % According RFC 6935 0x0000 checksum shall be replaced by 0xFFFF
      true -> Sum
    end;

makesum(Hdr) ->
	(checksum(Hdr) bxor 16#FFFF) band 16#FFFF. % bitwise-complement

%%Note:
%% - Checksum building for tunneled packets according to RFC 6936 is not supported
%% - Jumbo packets are not supported
%% - Extension headers are not supported

build_checksum([#ipv4{} = IP, #tcp{} = TCP, Payload]) -> % handle IPv4 TCP packets
    {ipv4_tcp, makesum(IP#ipv4{sum=0}), makesum([IP, TCP#tcp{sum = 0}, Payload])};

build_checksum([#ipv6{} = IP, #tcp{} = TCP, Payload]) -> % handle IPv6 TCP packets
    {ipv6_tcp, makesum([IP, TCP#tcp{sum = 0}, Payload])};

build_checksum([#ipv4{} = IP, #udp{} = UDP, Payload]) -> % handle IPv4 UDP packets
    {ipv4_udp, makesum(IP#ipv4{sum=0}), makesum([IP, UDP#udp{sum = 0}, Payload])};

build_checksum([#ipv6{} = IP, #udp{} = UDP, Payload])-> % handle IPv6 UDP packets
    {ipv6_udp, makesum([IP, UDP#udp{sum = 0}, Payload])}.


verify_checksum([#ipv4{} = IP, #tcp{} = TCP, Payload]) -> % handle IPv4 TCP packets
    build_checksum([IP, TCP, Payload]) == {ipv4_tcp, IP#ipv4.sum, TCP#tcp.sum};

verify_checksum([#ipv6{} = IP, #tcp{} = TCP, Payload]) -> % handle IPv6 TCP packets
    build_checksum([IP, TCP, Payload]) == {ipv6_tcp, TCP#tcp.sum};

verify_checksum([#ipv4{} = IP, #udp{} = UDP, Payload]) -> % handle IPv4 UDP packets
    if
      UDP#udp.sum == 0 -> % for ipv4 the UDP checksum is optional. According RFC 6935, the UDP checksum shall be ignored, when set to 0x0000.
        {ipv4_udp, IPv4sum, _} = build_checksum([IP, UDP, Payload]), % ignore UDP checksum, as UDP#udp.sum is 0
        if
          IPv4sum == IP#ipv4.sum ->
            true; % ok
          true ->
            false % checksum failure as IP4 checksum does not match
        end;
      true ->
          build_checksum([IP, UDP, Payload]) == {ipv4_udp, IP#ipv4.sum, UDP#udp.sum}
    end;

verify_checksum([#ipv6{} = IP, #udp{} = UDP, Payload]) -> % handle IPv6 UDP packets
    if
      UDP#udp.sum == 0 ->
        % for ipv6 the UDP packets, which contain the checksum 0x0000 are invalid according RFC 6935, they shall be discarded and an error shall be logged.
        false; % Thus set checksum as invalid
      true ->
        build_checksum([IP, UDP, Payload]) == {ipv6_udp, UDP#udp.sum}
    end.
