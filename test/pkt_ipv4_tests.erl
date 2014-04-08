-module(pkt_ipv4_tests).

-include_lib("pkt/include/pkt.hrl").
-include_lib("eunit/include/eunit.hrl").

codec_test_() ->
    [
        decode(),
        encode(),
        ipv4_udp_makesum_1(),
        ipv4_udp_makesum_2(),
        ipv4_udp_verify_checksum_1(),
        ipv4_udp_verify_checksum_2(),
        ipv4_tcp_makesum_1(),
        ipv4_tcp_makesum_2(),
        ipv4_tcp_verify_checksum_1(),
        ipv4_tcp_verify_checksum_2(),
        ipv4_udp_build_checksum_1(),
        ipv4_tcp_build_checksum_1()
    ].

packet() ->
    <<69,0,0,54,2,108,64,0,53,6,172,243,173,192,82,195,192,
      168,213,54,0,80,143,166,75,154,212,181,116,33,53,92,128,
      24,0,126,60,199,0,0,1,1,8,10,92,104,96,16,22,69,237,136,
      137,0>>.

decode() ->
    {Header, Payload} = pkt:ipv4(packet()),
    ?_assertEqual(
        {{ipv4,4,5,0,54,620,1,0,0,53,6,44275,
         {173,192,82,195},
         {192,168,213,54},
         <<>>},
         <<0,80,143,166,75,154,212,181,116,33,53,92,128,24,0,126,
           60,199,0,0,1,1,8,10,92,104,96,16,22,69,237,136,137,0>>},
         {Header, Payload}
    ).

encode() ->
    Packet = packet(),
    {Header, Payload} = pkt:ipv4(Packet),
    ?_assertEqual(Packet, <<(pkt:ipv4(Header))/binary, Payload/binary>>).


ipv4_udp_build_checksum_1() ->
    Result = pkt:build_checksum(ipv4_udp_packet_1()),
    ?_assertEqual(
        {ipv4_udp, 48969,37018},
        Result
    ).

ipv4_tcp_build_checksum_1() ->
    Result = pkt:build_checksum(ipv4_tcp_packet_1()),
    ?_assertEqual(
        {ipv4_tcp, 59801,49844},
        Result
    ).

ipv4_udp_packet_1() ->
    [#ipv4{v = 4,hl = 5,tos = 0,len = 328,id = 1946,df = 0,
       mf = 0,off = 0,ttl = 128,p = 17,sum = 48969,
       saddr = {192,168,178,25},
       daddr = {255,255,255,255},
       opt = <<>>},
     #udp{sport = 68,dport = 67,ulen = 308,sum = 37018},
     <<1,1,6,0,163,126,46,17,3,0,0,0,192,168,178,25,0,0,0,0,0,0,0,0,0,0,0,0,0,34,100,91,16,42,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
     0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
     0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
     0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
     0,0,0,0,0,0,0,99,130,83,99,53,1,8,61,7,1,0,34,100,91,16,42,12,10,109,105,99,104,97,101,108,45,80,67,60,8,77,83,70,84,32,
     53,46,48,55,13,1,15,3,6,44,46,47,31,33,121,249,43,252,255,0,0,0,0,0,0,0,0,0,0>>].

ipv4_udp_packet_2() ->
    [#ipv4{v = 4,hl = 5,tos = 0,len = 78,id = 1949,df = 0,
       mf = 0,off = 0,ttl = 128,p = 17,sum = 19608,
       saddr = {192,168,178,25},
       daddr = {192,168,178,255},
       opt = <<>>},
    #udp{sport = 137,dport = 137,ulen = 58,sum = 7692},
    <<184,131,1,16,0,1,0,0,0,0,0,0,32,70,72,70,65,69,66,69,69,67,65,67,65,67,65,67,65,67,65,67,65,67,65,67,65,67,65,67,65,67,65,65,65,0,0,32,0,1>>].

ipv4_udp_makesum_1() ->
    Checksum = pkt:makesum(ipv4_udp_packet_1()),
    ?_assertEqual(
        16#FFFF,
        Checksum
    ).

ipv4_udp_makesum_2() ->
    Checksum = pkt:makesum(ipv4_udp_packet_2()),
    ?_assertEqual(
        16#FFFF,
        Checksum
    ).

ipv4_udp_verify_checksum_1() ->
    Result = pkt:verify_checksum(ipv4_udp_packet_1()),
    ?_assertEqual(
        true,
        Result
    ).

ipv4_udp_verify_checksum_2() ->
    Result = pkt:verify_checksum(ipv4_udp_packet_2()),
    ?_assertEqual(
        true,
        Result
    ).

ipv4_tcp_packet_1() ->
    [#ipv4{v = 4,hl = 5,tos = 0,len = 60,id = 27574,df = 1,
       mf = 0,off = 0,ttl = 64,p = 6,sum = 59801,
       saddr = {192,168,178,1},
       daddr = {192,168,178,25},
       opt = <<>>},
     #tcp{sport = 49549,dport = 2869,seqno = 1351181078,
       ackno = 0,off = 10,cwr = 0,ece = 0,urg = 0,ack = 0,psh = 0,
       rst = 0,syn = 1,fin = 0,win = 5840,sum = 49844,urp = 0,
       opt = <<2,4,5,180,4,2,8,10,0,18,8,160,0,0,0,0,1,3,3,2>>},
       <<>>].

ipv4_tcp_packet_2() ->
    [#ipv4{v = 4,hl = 5,tos = 0,len = 40,id = 2642,df = 1,
       mf = 0,off = 0,ttl = 128,p = 6,sum = 50311,
       saddr = {192,168,178,25},
       daddr = {81,19,104,33},
       opt = <<>>},
     #tcp{sport = 49443,dport = 443,seqno = 3493555953,
      ackno = 2085059857,off = 5,cwr = 0,ece = 0,urg = 0,ack = 1,
      psh = 0,rst = 0,syn = 0,fin = 0,win = 16652,sum = 18285,
      urp = 0,opt = <<>>},
     <<0,0,0,0,0,0>>].

ipv4_tcp_makesum_1() ->
    Checksum = pkt:makesum(ipv4_tcp_packet_1()),
    ?_assertEqual(
        0,
        Checksum
    ).

ipv4_tcp_makesum_2() ->
    Checksum = pkt:makesum(ipv4_tcp_packet_2()),
    ?_assertEqual(
        0,
        Checksum
    ).

ipv4_tcp_verify_checksum_1() ->
    Result = pkt:verify_checksum(ipv4_tcp_packet_1()),
    ?_assertEqual(
        true,
        Result
    ).

ipv4_tcp_verify_checksum_2() ->
    Result = pkt:verify_checksum(ipv4_tcp_packet_2()),
    ?_assertEqual(
        true,
        Result
    ).
