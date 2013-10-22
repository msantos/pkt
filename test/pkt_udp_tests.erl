-module(pkt_udp_tests).

-include_lib("pkt/include/pkt.hrl").
-include_lib("eunit/include/eunit.hrl").

codec_test_() ->
    [
        decode(),
        encode()
    ].

packet() ->
    <<130,117,122,105,0,14,166,14,116,101,115,101,116,10>>.

decode() ->
    {Header, Payload} = pkt:udp(packet()),
    ?_assertEqual(
        {{udp,33397,31337,14,42510},<<"teset\n">>},
        {Header, Payload}
    ).

encode() ->
    Packet = packet(),
    {Header, Payload} = pkt:udp(Packet),
    ?_assertEqual(Packet, <<(pkt:udp(Header))/binary, Payload/binary>>).
