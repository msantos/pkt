-module(pkt_ipv6_hopopts_tests).

-include_lib("pkt/include/pkt.hrl").
-include_lib("eunit/include/eunit.hrl").

codec_test_() ->
    [
        decode(),
        encode()
    ].

packet() ->
    <<58,0,5,2,0,0,1,0,131,0,74,228,0,0,0,0,
      255,2,0,0,0,0,0,0,0,0,0,1,255,5,14,187>>.

decode() ->
    {Header, Payload} = pkt:ipv6_hopopts(packet()),
    ?_assertEqual(
        {{ipv6_hopopts,58,0,<<5,2,0,0,1,0>>},
          <<131,0,74,228,0,0,0,0,255,2,0,0,0,0,0,0,0,0,0,1,255,5,
            14,187>>},
        {Header, Payload}
    ).

encode() ->
    Packet = packet(),
    {Header, Payload} = pkt:ipv6_hopopts(Packet),
    ?_assertEqual(Packet, <<(pkt:ipv6_hopopts(Header))/binary, Payload/binary>>).
