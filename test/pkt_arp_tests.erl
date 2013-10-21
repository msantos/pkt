-module(pkt_arp_tests).

-include_lib("pkt/include/pkt.hrl").
-include_lib("eunit/include/eunit.hrl").

arp_test_() ->
    [
        decode(),
        encode()
    ].

packet() ->
    <<255,255,255,255,255,255,0,22,182,181,62,198,
      8,6,0,1,8,0,6,4,0,1,0,22,182,181,62,198,192,
      168,213,1,0,0,0,0,0,0,192,168,213,128,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,129,1,10,104>>.

decode() ->
    {ARP, Payload} = pkt:arp(packet()),
    ?_assertEqual(
        {{arp,65535,65535,255,255,22,
          <<182,181,62,198,8,6>>,
          {0,1,8,0},
          <<6,4,0,1,0,22>>,
          {182,181,62,198}},
          <<192,168,213,1,0,0,0,0,0,0,192,168,213,128,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,129,1,10,104>>},
        {ARP, Payload}
    ).

encode() ->
    Packet = packet(),
    {ARP, Payload} = pkt:arp(Packet),
    ?_assertEqual(Packet, <<(pkt:arp(ARP))/binary, Payload/binary>>).
