-module(pkt_icmp6_tests).

-include_lib("pkt/include/pkt.hrl").
-include_lib("eunit/include/eunit.hrl").

codec_test_() ->
    [
        decode(),
        encode()
    ].

packet() ->
    <<128,0,255,149,7,79,0,1,169,244,102,82,0,0,0,0,36,187,0,
      0,0,0,0,0,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,
      31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,
      49,50,51,52,53,54,55>>.

decode() ->
    {Header, Payload} = pkt:icmp6(packet()),
    ?_assertEqual(
        {{icmp6,128,0,65429,<<0,0,0,0>>,0,0,1871,1,0},
          <<169,244,102,82,0,0,0,0,36,187,0,0,0,0,0,0,16,17,18,19,
            20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,
            38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55>>},
        {Header, Payload}
    ).

encode() ->
    Packet = packet(),
    {Header, Payload} = pkt:icmp6(Packet),
    ?_assertEqual(Packet, <<(pkt:icmp6(Header))/binary, Payload/binary>>).
