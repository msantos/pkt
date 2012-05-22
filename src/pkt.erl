%% Copyright (c) 2009-2012, Michael Santos <michael.santos@gmail.com>
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
        decapsulate/1,
        decapsulate_dlt/2,
        makesum/1,
        valid/1,
        ether/1,
        ether_type/1,
        link_type/1,
        arp/1,
        null/1,
        linux_cooked/1,
        icmp/1,
        icmp6/1,
        ipv4/1,
        ipv6/1,
        proto/1,
        tcp/1,
        udp/1,
        dlt/1
]).


decapsulate_dlt(Dlt, Data) ->
    decapsulate({link_type(Dlt), Data}, []).


decapsulate({DLT, Data}) when is_integer(DLT) ->
    decapsulate({link_type(DLT), Data}, []);
decapsulate({DLT, Data}) when is_atom(DLT) ->
    decapsulate({DLT, Data}, []);
decapsulate(Data) when is_binary(Data) ->
    decapsulate({ether, Data}, []).

decapsulate(stop, Packet) ->
    lists:reverse(Packet);

decapsulate({unsupported, Data}, Packet) ->
    decapsulate(stop, [{unsupported, Data}|Packet]);

decapsulate({null, Data}, Packet) when byte_size(Data) >= 16 ->
    {Hdr, Payload} = null(Data),
    decapsulate({family(Hdr#null.family), Payload}, [Hdr|Packet]);
decapsulate({linux_cooked, Data}, Packet) when byte_size(Data) >= 16 ->
    {Hdr, Payload} = linux_cooked(Data),
    decapsulate({ether_type(Hdr#linux_cooked.pro), Payload}, [Hdr|Packet]);
decapsulate({ether, Data}, Packet) when byte_size(Data) >= ?ETHERHDRLEN ->
    {Hdr, Payload} = ether(Data),
    decapsulate({ether_type(Hdr#ether.type), Payload}, [Hdr|Packet]);
decapsulate({arp, Data}, Packet) when byte_size(Data) >= 28 -> % IPv4 ARP
    {Hdr, Payload} = arp(Data),
    decapsulate(stop, [Payload, Hdr|Packet]);

decapsulate({ipv4, Data}, Packet) when byte_size(Data) >= ?IPV4HDRLEN ->
    {Hdr, Payload} = ipv4(Data),
    decapsulate({proto(Hdr#ipv4.p), Payload}, [Hdr|Packet]);
decapsulate({ipv6, Data}, Packet) when byte_size(Data) >= ?IPV6HDRLEN ->
    {Hdr, Payload} = ipv6(Data),
    decapsulate({proto(Hdr#ipv6.next), Payload}, [Hdr|Packet]);
%% GRE
decapsulate({gre, Data}, Packet) when byte_size(Data) >= ?GREHDRLEN ->
    {Hdr, Payload} = gre(Data),
    decapsulate({ether_type(Hdr#gre.type), Payload}, [Hdr|Packet]);

decapsulate({tcp, Data}, Packet) when byte_size(Data) >= ?TCPHDRLEN ->
    {Hdr, Payload} = tcp(Data),
    decapsulate(stop, [Payload, Hdr|Packet]);
decapsulate({udp, Data}, Packet) when byte_size(Data) >= ?UDPHDRLEN ->
    {Hdr, Payload} = udp(Data),
    decapsulate(stop, [Payload, Hdr|Packet]);
decapsulate({sctp, Data}, Packet) when byte_size(Data) >= 12 ->
    {Hdr, Payload} = sctp(Data),
    decapsulate(stop, [Payload, Hdr|Packet]);
decapsulate({icmp, Data}, Packet) when byte_size(Data) >= ?ICMPHDRLEN ->
    {Hdr, Payload} = icmp(Data),
    decapsulate(stop, [Payload, Hdr|Packet]);
decapsulate({icmp6, Data}, Packet) when byte_size(Data) >= ?ICMP6HDRLEN ->
    {Hdr, Payload} = icmp6(Data),
    decapsulate(stop, [Payload, Hdr|Packet]);
decapsulate({_, Data}, Packet) ->
    decapsulate(stop, [{truncated, Data}|Packet]).


ether_type(?ETH_P_IP) -> ipv4;
ether_type(?ETH_P_IPV6) -> ipv6;
ether_type(?ETH_P_ARP) -> arp;
ether_type(_) -> unsupported.

link_type(?DLT_NULL) -> null;
link_type(?DLT_EN10MB) -> ether;
link_type(?DLT_LINUX_SLL) -> linux_cooked;
link_type(_) -> unsupported.

family(?PF_INET) -> ipv4;
family(?PF_INET6) -> ipv6;
family(_) -> unsupported.

proto(?IPPROTO_ICMP) -> icmp;
proto(?IPPROTO_ICMPV6) -> icmp6;
proto(?IPPROTO_TCP) -> tcp;
proto(?IPPROTO_UDP) -> udp;
proto(?IPPROTO_SCTP) -> sctp;
proto(?IPPROTO_GRE) -> gre;
proto(?IPPROTO_RAW) -> raw;
proto(_) -> unsupported.


%%
%% BSD loopback
%%
null(<<Family:4/native-unsigned-integer-unit:8, Payload/binary>>) ->
    {#null{
            family = Family
        }, Payload};
null(#null{family = Family}) ->
    <<Family:4/native-unsigned-integer-unit:8>>.

%%
%% Linux cooked capture ("-i any") - DLT_LINUX_SLL
%%
linux_cooked(<<Ptype:16/big, Hrd:16/big, Ll_len:16/big,
               Ll_hdr:8/bytes, Pro:16, Payload/binary>>) ->
    {#linux_cooked{
        packet_type = Ptype, hrd = Hrd,
        ll_len = Ll_len, ll_bytes = Ll_hdr,
        pro = Pro
      }, Payload};
linux_cooked(#linux_cooked{
              packet_type = Ptype, hrd = Hrd,
              ll_len = Ll_len, ll_bytes = Ll_hdr,
              pro = Pro
             }) ->
    <<Ptype:16/big, Hrd:16/big, Ll_len:16/big,
      Ll_hdr:8/bytes, Pro:16>>.

%%
%% Ethernet
%%
ether(<<Dhost:6/bytes, Shost:6/bytes, Type:16, Payload/binary>>) ->
%    Len = byte_size(Packet) - 4,
%    <<Payload:Len/bytes, CRC:4/bytes>> = Packet,
    {#ether{
       dhost = Dhost, shost = Shost,
       type = Type
      }, Payload};
ether(#ether{
       dhost = Dhost, shost = Shost,
       type = Type
      }) ->
    <<Dhost:6/bytes, Shost:6/bytes, Type:16>>.

%%
%% ARP
%%
arp(<<Hrd:16, Pro:16,
    Hln:8, Pln:8, Op:16,
    Sha:6/bytes,
    SA1:8, SA2:8, SA3:8, SA4:8,
    Tha:6/bytes,
    DA1:8, DA2:8, DA3:8, DA4:8,
    Payload/binary>>
) ->
    {#arp{
        hrd = Hrd, pro = Pro,
        hln = Hln, pln = Pln, op = Op,
        sha = Sha,
        sip = {SA1,SA2,SA3,SA4},
        tha = Tha,
        tip = {DA1,DA2,DA3,DA4}
    }, Payload};
arp(#arp{
        hrd = Hrd, pro = Pro,
        hln = Hln, pln = Pln, op = Op,
        sha = Sha,
        sip = {SA1,SA2,SA3,SA4},
        tha = Tha,
        tip = {DA1,DA2,DA3,DA4}
    }) ->
    <<Hrd:16, Pro:16,
    Hln:8, Pln:8, Op:16,
    Sha:6/bytes,
    SA1:8, SA2:8, SA3:8, SA4:8,
    Tha:6/bytes,
    DA1:8, DA2:8, DA3:8, DA4:8>>.


%%
%% IPv4
%%
ipv4(
    <<4:4, HL:4, ToS:8, Len:16,
    Id:16, 0:1, DF:1, MF:1, %% RFC791 states it's a MUST
    Off:13, TTL:8, P:8, Sum:16,
    SA1:8, SA2:8, SA3:8, SA4:8,
    DA1:8, DA2:8, DA3:8, DA4:8,
    Rest/binary>>
) when HL >= 5 ->
    {Opt, Payload} = options(HL, Rest),
    {#ipv4{
        hl = HL, tos = ToS, len = Len,
        id = Id, df = DF, mf = MF,
        off = Off, ttl = TTL, p = P, sum = Sum,
        saddr = {SA1,SA2,SA3,SA4},
        daddr = {DA1,DA2,DA3,DA4},
        opt = Opt
    }, Payload};
ipv4(#ipv4{
        hl = HL, tos = ToS, len = Len,
        id = Id, df = DF, mf = MF,
        off = Off, ttl = TTL, p = P, sum = Sum,
        saddr = {SA1,SA2,SA3,SA4},
        daddr = {DA1,DA2,DA3,DA4}
    }) ->
    <<4:4, HL:4, ToS:8, Len:16,
    Id:16, 0:1, DF:1, MF:1, %% RFC791 states it's a MUST
    Off:13, TTL:8, P:8, Sum:16,
    SA1:8, SA2:8, SA3:8, SA4:8,
    DA1:8, DA2:8, DA3:8, DA4:8>>.


%%
%% IPv6
%%
ipv6(
    <<6:4, Class:8, Flow:20,
    Len:16, Next:8, Hop:8,
    SA1:16, SA2:16, SA3:16, SA4:16, SA5:16, SA6:16, SA7:16, SA8:16,
    DA1:16, DA2:16, DA3:16, DA4:16, DA5:16, DA6:16, DA7:16, DA8:16,
    Payload/binary>>
) ->
    {#ipv6{
        class = Class, flow = Flow,
        len = Len, next = Next, hop = Hop,
        saddr = {SA1, SA2, SA3, SA4, SA5, SA6, SA7, SA8},
        daddr = {DA1, DA2, DA3, DA4, DA5, DA6, DA7, DA8}
    }, Payload};
ipv6(#ipv6{
        class = Class, flow = Flow,
        len = Len, next = Next, hop = Hop,
        saddr = {SA1, SA2, SA3, SA4, SA5, SA6, SA7, SA8},
        daddr = {DA1, DA2, DA3, DA4, DA5, DA6, DA7, DA8}
    }) ->
    <<6:4, Class:8, Flow:20,
    Len:16, Next:8, Hop:8,
    SA1:16, SA2:16, SA3:16, SA4:16, SA5:16, SA6:16, SA7:16, SA8:16,
    DA1:16, DA2:16, DA3:16, DA4:16, DA5:16, DA6:16, DA7:16, DA8:16>>.

%%
%% GRE
%%
gre(<<0:1,Res0:12,Ver:3,Type:16,Rest/binary>>) ->
    {#gre{c = 0, res0 = Res0, ver = Ver, type = Type
       },Rest
    };
gre(<<1:1,Res0:12,Ver:3,Type:16,Chksum:16,Res1:16,Rest/binary>>) ->
    {#gre{c = 1, res0 = Res0, ver = Ver, type = Type,
	chksum = Chksum, res1 = Res1
       },Rest
    };
gre(#gre{c = 0, res0 = Res0, ver = Ver, type = Type}) ->
    <<0:1,Res0:12,Ver:3,Type:16>>;
gre(#gre{c = 1, res0 = Res0, ver = Ver, type = Type,
	chksum = Chksum, res1 = Res1}) ->
    <<1:1,Res0:12,Ver:3,Type:16,Chksum:16,Res1:16>>.

%%
%% TCP
%%
tcp(
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
tcp(#tcp{
        sport = SPort, dport = DPort,
        seqno = SeqNo,
        ackno = AckNo,
        off = Off, cwr = CWR, ece = ECE, urg = URG, ack = ACK,
            psh = PSH, rst = RST, syn = SYN, fin = FIN, win = Win,
        sum = Sum, urp = Urp
    }) ->
    <<SPort:16, DPort:16,
      SeqNo:32,
      AckNo:32,
      Off:4, 0:4, CWR:1, ECE:1, URG:1, ACK:1,
          PSH:1, RST:1, SYN:1, FIN:1, Win:16,
      Sum:16, Urp:16>>.

options(Offset, Payload) ->
    N = (Offset-5)*4,
    <<Opt:N/binary, Payload1/binary>> = Payload,
    {Opt, Payload1}.

%%
%% SCTP
%%
sctp(<<SPort:16, DPort:16, VTag:32, Sum:32, Payload/binary>>) ->
	{#sctp{sport = SPort, dport = DPort, vtag = VTag, sum = Sum,
	 chunks=sctp_chunk_list_gen(Payload)}, []}.

sctp_chunk_list_gen(Payload) ->
	sctp_chunk_list_gen(Payload, []).

sctp_chunk_list_gen(Payload, List) ->
	% chop the first chunk off the payload
	case sctp_chunk_chop(Payload) of
		{Chunk, Remainder} ->
			% loop
			sctp_chunk_list_gen(Remainder, [Chunk|List]);
		[] ->
			List
	end.

sctp_chunk_chop(<<>>) ->
	[];
sctp_chunk_chop(<<Ctype:8, Cflags:8, Clen:16, Remainder/binary>>) ->
	Payload = binary:part(Remainder, 0, Clen-4),
	Tail = binary:part(Remainder, Clen-4, byte_size(Remainder)-(Clen-4)),
	{sctp_chunk(Ctype, Cflags, Clen, Payload), Tail}.

sctp_chunk(Ctype, Cflags, Clen, Payload) ->
	#sctp_chunk{type=Ctype, flags=Cflags, len = Clen-4,
		    payload=sctp_chunk_payload(Ctype, Payload)}.

sctp_chunk_payload(0, <<Tsn:32, Sid:16, Ssn:16, Ppi:32, Data/binary>>) ->
	#sctp_chunk_data{tsn=Tsn, sid=Sid, ssn=Ssn, ppi=Ppi, data=Data};
sctp_chunk_payload(_, Data) ->
	Data.


%%
%% UDP
%%
udp(<<SPort:16, DPort:16, ULen:16, Sum:16, Payload/binary>>) ->
    {#udp{sport = SPort, dport = DPort, ulen = ULen, sum = Sum}, Payload};
udp(#udp{sport = SPort, dport = DPort, ulen = ULen, sum = Sum}) ->
    <<SPort:16, DPort:16, ULen:16, Sum:16>>.


%%
%% ICMP
%%

% Destination Unreachable Message
icmp(<<?ICMP_DEST_UNREACH:8, Code:8, Checksum:16, Unused:32/bits, Payload/binary>>) ->
    {#icmp{
        type = ?ICMP_DEST_UNREACH, code = Code, checksum = Checksum, un = Unused
    }, Payload};
icmp(#icmp{
        type = ?ICMP_DEST_UNREACH, code = Code, checksum = Checksum, un = Unused
    }) ->
    <<?ICMP_DEST_UNREACH:8, Code:8, Checksum:16, Unused:32/bits>>;

% Time Exceeded Message
icmp(<<?ICMP_TIME_EXCEEDED:8, Code:8, Checksum:16, Unused:32/bits, Payload/binary>>) ->
    {#icmp{
        type = ?ICMP_TIME_EXCEEDED, code = Code, checksum = Checksum, un = Unused
    }, Payload};
icmp(#icmp{
        type = ?ICMP_TIME_EXCEEDED, code = Code, checksum = Checksum, un = Unused
    }) ->
    <<?ICMP_TIME_EXCEEDED:8, Code:8, Checksum:16, Unused:32/bits>>;

% Parameter Problem Message
icmp(<<?ICMP_PARAMETERPROB:8, Code:8, Checksum:16, Pointer:8, Unused:24/bits, Payload/binary>>) ->
    {#icmp{
        type = ?ICMP_PARAMETERPROB, code = Code, checksum = Checksum, pointer = Pointer,
        un = Unused
    }, Payload};
icmp(#icmp{
        type = ?ICMP_PARAMETERPROB, code = Code, checksum = Checksum, pointer = Pointer,
        un = Unused
    }) ->
    <<?ICMP_PARAMETERPROB:8, Code:8, Checksum:16, Pointer:8, Unused:24/bits>>;

% Source Quench Message
icmp(<<?ICMP_SOURCE_QUENCH:8, 0:8, Checksum:16, Unused:32/bits, Payload/binary>>) ->
    {#icmp{
        type = ?ICMP_SOURCE_QUENCH, code = 0, checksum = Checksum, un = Unused
    }, Payload};
icmp(#icmp{
        type = ?ICMP_SOURCE_QUENCH, code = Code, checksum = Checksum, un = Unused
    }) ->
    <<?ICMP_SOURCE_QUENCH:8, Code:8, Checksum:16, Unused:32/bits>>;

% Redirect Message
icmp(<<?ICMP_REDIRECT:8, Code:8, Checksum:16, DA1, DA2, DA3, DA4, Payload/binary>>) ->
    {#icmp{
        type = ?ICMP_REDIRECT, code = Code, checksum = Checksum, gateway = {DA1,DA2,DA3,DA4}
    }, Payload};
icmp(#icmp{
        type = ?ICMP_REDIRECT, code = Code, checksum = Checksum, gateway = {DA1,DA2,DA3,DA4}
    }) ->
    <<?ICMP_REDIRECT:8, Code:8, Checksum:16, DA1, DA2, DA3, DA4>>;

% Echo or Echo Reply Message
icmp(<<Type:8, Code:8, Checksum:16, Id:16, Sequence:16, Payload/binary>>)
when Type =:= ?ICMP_ECHO; Type =:= ?ICMP_ECHOREPLY ->
    {#icmp{
        type = Type, code = Code, checksum = Checksum, id = Id,
        sequence = Sequence
    }, Payload};
icmp(#icmp{
        type = Type, code = Code, checksum = Checksum, id = Id,
        sequence = Sequence
    })
when Type =:= ?ICMP_ECHO; Type =:= ?ICMP_ECHOREPLY ->
    <<Type:8, Code:8, Checksum:16, Id:16, Sequence:16>>;

% Timestamp or Timestamp Reply Message
icmp(<<Type:8, 0:8, Checksum:16, Id:16, Sequence:16, TS_Orig:32, TS_Recv:32, TS_Tx:32>>)
when Type =:= ?ICMP_TIMESTAMP; Type =:= ?ICMP_TIMESTAMPREPLY ->
    {#icmp{
        type = Type, code = 0, checksum = Checksum, id = Id,
        sequence = Sequence, ts_orig = TS_Orig, ts_recv = TS_Recv, ts_tx = TS_Tx
    }, <<>>};
icmp(#icmp{
        type = Type, code = Code, checksum = Checksum, id = Id,
        sequence = Sequence, ts_orig = TS_Orig, ts_recv = TS_Recv, ts_tx = TS_Tx
    }) when Type =:= ?ICMP_TIMESTAMP; Type =:= ?ICMP_TIMESTAMPREPLY ->
    <<Type:8, Code:8, Checksum:16, Id:16, Sequence:16, TS_Orig:32, TS_Recv:32, TS_Tx:32>>;

% Information Request or Information Reply Message
icmp(<<Type:8, 0:8, Checksum:16, Id:16, Sequence:16>>)
when Type =:= ?ICMP_INFO_REQUEST; Type =:= ?ICMP_INFO_REPLY ->
    {#icmp{
        type = Type, code = 0, checksum = Checksum, id = Id,
        sequence = Sequence
    }, <<>>};
icmp(#icmp{
        type = Type, code = Code, checksum = Checksum, id = Id,
        sequence = Sequence
    }) when Type =:= ?ICMP_INFO_REQUEST; Type =:= ?ICMP_INFO_REPLY ->
    <<Type:8, Code:8, Checksum:16, Id:16, Sequence:16>>;

% Catch/build arbitrary types
icmp(<<Type:8, Code:8, Checksum:16, Un:32, Payload/binary>>) ->
    {#icmp{
        type = Type, code = Code, checksum = Checksum, un = Un
    }, Payload};
icmp(#icmp{type = Type, code = Code, checksum = Checksum, un = Un}) ->
    <<Type:8, Code:8, Checksum:16, Un:32>>.


%%
%% ICMPv6
%%

% ICMPv6 Error Messages

% Destination Unreachable Message
icmp6(<<?ICMP6_DST_UNREACH:8, Code:8, Checksum:16, Unused:32/bits, Payload/binary>>) ->
    {#icmp6{
        type = ?ICMP6_DST_UNREACH, code = Code, checksum = Checksum, un = Unused
    }, Payload};
icmp6(#icmp6{
        type = ?ICMP6_DST_UNREACH, code = Code, checksum = Checksum, un = Unused
    }) ->
    <<?ICMP6_DST_UNREACH:8, Code:8, Checksum:16, Unused:32/bits>>;

% Packet too big
icmp6(<<?ICMP6_PACKET_TOO_BIG:8, Code:8, Checksum:16, MTU:32, Payload/binary>>) ->
    {#icmp6{
        type = ?ICMP6_PACKET_TOO_BIG, code = Code, checksum = Checksum, mtu = MTU
    }, Payload};
icmp6(#icmp6{
        type = ?ICMP6_PACKET_TOO_BIG, code = Code, checksum = Checksum, mtu = MTU
    }) ->
    <<?ICMP6_PACKET_TOO_BIG:8, Code:8, Checksum:16, MTU:32>>;

% Time Exceeded Message
icmp6(<<?ICMP6_TIME_EXCEEDED:8, Code:8, Checksum:16, Unused:32/bits, Payload/binary>>) ->
    {#icmp6{
        type = ?ICMP6_TIME_EXCEEDED, code = Code, checksum = Checksum, un = Unused
    }, Payload};
icmp6(#icmp6{
        type = ?ICMP6_TIME_EXCEEDED, code = Code, checksum = Checksum, un = Unused
    }) ->
    <<?ICMP6_TIME_EXCEEDED:8, Code:8, Checksum:16, Unused:32/bits>>;

% Parameter Problem Message
icmp6(<<?ICMP6_PARAM_PROB:8, Code:8, Checksum:16, Ptr:32, Payload/binary>>) ->
    {#icmp6{
        type = ?ICMP6_PARAM_PROB, code = Code, checksum = Checksum, pptr = Ptr
    }, Payload};
icmp6(#icmp6{
        type = ?ICMP6_PARAM_PROB, code = Code, checksum = Checksum, pptr = Ptr
    }) ->
    <<?ICMP6_PARAM_PROB:8, Code:8, Checksum:16, Ptr:32>>;

% ICMPv6 Informational Messages

% Echo Request Message/Echo Reply Message
icmp6(<<Type:8, Code:8, Checksum:16, Id:16, Seq:16, Payload/binary>>)
        when Type =:= ?ICMP6_ECHO_REQUEST; Type =:= ?ICMP6_ECHO_REPLY ->
    {#icmp6{
        type = Type, code = Code, checksum = Checksum,
        id = Id, seq = Seq
    }, Payload};
icmp6(#icmp6{
        type = Type, code = Code, checksum = Checksum,
        id = Id, seq = Seq
    }) when Type =:= ?ICMP6_ECHO_REQUEST; Type =:= ?ICMP6_ECHO_REPLY ->
    <<Type:8, Code:8, Checksum:16, Id:16, Seq:16>>.


%%
%% Utility functions
%%

% TCP pseudoheader checksum
checksum([#ipv4{
        saddr = {SA1,SA2,SA3,SA4},
        daddr = {DA1,DA2,DA3,DA4}
    },
    #tcp{
        off = Off
    } = TCPhdr,
    Payload
]) ->
    Len = Off * 4,
    TCP = tcp(TCPhdr#tcp{sum = 0}),
    Pad = case Len rem 2 of
        0 -> 0;
        1 -> 8
    end,
    checksum(
        <<SA1,SA2,SA3,SA4,
          DA1,DA2,DA3,DA4,
          0:8,
          ?IPPROTO_TCP:8,
          Len:16,
          TCP/binary,
          Payload/bits,
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
    UDP = udp(Hdr#udp{sum = 0}),
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

valid(16#FFFF) -> true;
valid(_) -> false.


%%
%% Datalink types
%%
dlt(?DLT_NULL) -> null;
dlt(?DLT_EN10MB) -> en10mb;
dlt(?DLT_EN3MB) -> en3mb;
dlt(?DLT_AX25) -> ax25;
dlt(?DLT_PRONET) -> pronet;
dlt(?DLT_CHAOS) -> chaos;
dlt(?DLT_IEEE802) -> ieee802;
dlt(?DLT_ARCNET) -> arcnet;
dlt(?DLT_SLIP) -> slip;
dlt(?DLT_PPP) -> ppp;
dlt(?DLT_FDDI) -> fddi;
dlt(?DLT_ATM_RFC1483) -> atm_rfc1483;
dlt(?DLT_RAW) -> raw;
dlt(?DLT_SLIP_BSDOS) -> slip_bsdos;
dlt(?DLT_PPP_BSDOS) -> ppp_bsdos;
dlt(?DLT_PFSYNC) -> pfsync;
dlt(?DLT_ATM_CLIP) -> atm_clip;
dlt(?DLT_PPP_SERIAL) -> ppp_serial;
%dlt(?DLT_C_HDLC) -> c_hdlc;
dlt(?DLT_CHDLC) -> chdlc;
dlt(?DLT_IEEE802_11) -> ieee802_11;
dlt(?DLT_LOOP) -> loop;
dlt(?DLT_LINUX_SLL) -> linux_sll;
dlt(?DLT_PFLOG) -> pflog;
dlt(?DLT_IEEE802_11_RADIO) -> ieee802_11_radio;
dlt(?DLT_APPLE_IP_OVER_IEEE1394) -> apple_ip_over_ieee1394;
dlt(?DLT_IEEE802_11_RADIO_AVS) -> ieee802_11_radio_avs;

dlt(null) -> ?DLT_NULL;
dlt(en10mb) -> ?DLT_EN10MB;
dlt(en3mb) -> ?DLT_EN3MB;
dlt(ax25) -> ?DLT_AX25;
dlt(pronet) -> ?DLT_PRONET;
dlt(chaos) -> ?DLT_CHAOS;
dlt(ieee802) -> ?DLT_IEEE802;
dlt(arcnet) -> ?DLT_ARCNET;
dlt(slip) -> ?DLT_SLIP;
dlt(ppp) -> ?DLT_PPP;
dlt(fddi) -> ?DLT_FDDI;
dlt(atm_rfc1483) -> ?DLT_ATM_RFC1483;
dlt(raw) -> ?DLT_RAW;
dlt(slip_bsdos) -> ?DLT_SLIP_BSDOS;
dlt(ppp_bsdos) -> ?DLT_PPP_BSDOS;
dlt(pfsync) -> ?DLT_PFSYNC;
dlt(atm_clip) -> ?DLT_ATM_CLIP;
dlt(ppp_serial) -> ?DLT_PPP_SERIAL;
dlt(c_hdlc) -> ?DLT_C_HDLC;
dlt(chdlc) -> ?DLT_CHDLC;
dlt(ieee802_11) -> ?DLT_IEEE802_11;
dlt(loop) -> ?DLT_LOOP;
dlt(linux_sll) -> ?DLT_LINUX_SLL;
dlt(pflog) -> ?DLT_PFLOG;
dlt(ieee802_11_radio) -> ?DLT_IEEE802_11_RADIO;
dlt(apple_ip_over_ieee1394) -> ?DLT_APPLE_IP_OVER_IEEE1394;
dlt(ieee802_22_radio_avs) -> ?DLT_IEEE802_11_RADIO_AVS.
