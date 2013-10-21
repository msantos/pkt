-module(pkt_ether_tests).

-include_lib("pkt/include/pkt.hrl").
-include_lib("eunit/include/eunit.hrl").

tcp_test_() ->
    [
        decode(),
        encode()
    ].

packet() ->
    <<0,80,217,184,222,13,22,43,241,75,9,12,176,18,17,4,140,86,
      0,0,2,4,5,172,1, 3,3,0,1,1,8,10,190,15,172,236,0,64,161,73,4,2,0,0>>.

decode() ->
    {Ether, Payload} = pkt:ether(packet()),
    ?_assertEqual(
        {{ether,<<0,80,217,184,222,13>>,
         <<22,43,241,75,9,12>>,
         45074,0},
         <<17,4,140,86,0,0,2,4,5,172,1,3,3,0,1,1,8,10,190,15,172,
         236,0,64,161,73,4,2,0,0>>},
         {Ether, Payload}
    ).

encode() ->
    Packet = packet(),
    {Ether, Payload} = pkt:ether(Packet),
    ?_assertEqual(Packet, <<(pkt:ether(Ether))/binary, Payload/binary>>).
