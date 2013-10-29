-module(pkt_igmp_tests).

-include_lib("pkt/include/pkt.hrl").
-include_lib("eunit/include/eunit.hrl").

codec_test_() ->
    [
        decode(),
        encode()
    ].

packet() ->
    <<17,100,238,155,0,0,0,0>>.

decode() ->
    {Header, Payload} = pkt:igmp(packet()),
    ?_assertEqual(
        {#igmp{type = 17,code = 100,csum = 61083,group = {0,0,0,0}},
               <<>>},
        {Header, Payload}
    ).

encode() ->
    Packet = packet(),
    {Header, Payload} = pkt:igmp(Packet),
    ?_assertEqual(Packet, <<(pkt:igmp(Header))/binary, Payload/binary>>).
