-module(pkt_tcp_tests).

-include_lib("pkt/include/pkt.hrl").
-include_lib("eunit/include/eunit.hrl").

tcp_test_() ->
    [
        tcp_decode_encode(),
        tcp_checksum4()
    ].

tcp_decode_encode() ->
    Packet = <<0,80,217,184,222,13,22,43,241,75,9,12,176,18,17,4,140,86,
        0,0,2,4,5,172,1, 3,3,0,1,1,8,10,190,15,172,236,0,64,161,73,4,2,0,0>>,
    {TCP, <<>>} = pkt:tcp(Packet),
    TCP1 = TCP#tcp{opt = pkt:tcp_options(pkt:tcp_options(TCP#tcp.opt))},
    ?_assertEqual(Packet, pkt:tcp(TCP1)).

tcp_checksum4() ->
    Frame = <<224,105,149,59,163,24,0,22,182,181,62,198,8,0,69,0,0,54,2,108,64,
              0,53,6,172,243,173,192,82,195,192,168,213,54,0,80,143,166,75,154,
              212,181,116,33,53,92,128,24,0,126,60,199,0,0,1,1,8,10,92,104,96,
              16,22,69,237,136,137,0>>,

    [#ether{}, IPv4, #tcp{sum = Sum} = TCP, Payload] = pkt:decapsulate(Frame),

    Sum = pkt:makesum([IPv4, TCP#tcp{sum = 0}, Payload]),
    ?_assertEqual(0, pkt:makesum([IPv4, TCP, Payload])).
