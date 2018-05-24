-module(pkt_gre_tests).

-include_lib("pkt/include/pkt.hrl").
-include_lib("eunit/include/eunit.hrl").

codec_test_() ->
    [
        decode(),
        encode()
    ].

packet() ->
    <<48,0,8,0,0,0,48,57,0,0,0,1,
        69,0,0,20,0,0,0,0,64,6,0,0,127,0,0,1,127,0,0,1>>.

decode() ->
    {Header, Payload} = pkt:gre(packet()),
    ?_assertEqual(
        {{gre,0,0,1,1,0,0,2048,0,0,12345,1},
         <<69,0,0,20,0,0,0,0,64,6,0,0,127,0,0,1,127,0,0,1>>},
        {Header, Payload}
    ).

encode() ->
    Packet = packet(),
    {Header, Payload} = pkt:gre(Packet),
    ?_assertEqual(Packet, <<(pkt:gre(Header))/binary, Payload/binary>>).
