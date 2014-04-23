-module(pkt_igmp_tests).

-include_lib("pkt/include/pkt.hrl").
-include_lib("eunit/include/eunit.hrl").

codec_test_() ->
    [
        decode(),
        encode(),
        decode_igmpv3_22(),
        encode_igmpv3_22()
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


packet_igmp_22() ->
    <<16#22, 0, 235,252, 0,0,0,1, 3,0,0,0,239,0,0,1>>.

decode_igmpv3_22() ->
    {Header, Payload} = pkt:igmp(packet_igmp_22()),
    ?_assertEqual({
        #igmp{type = 34, code = 0, csum = 60412, group = [#igmp_group{type = 3, addr = {239,0,0,1}} ]},
        <<>>
    }, {Header, Payload}).

encode_igmpv3_22() ->
    Packet = packet_igmp_22(),
    {Header, Payload} = pkt:igmp(Packet),
    ?_assertEqual(Packet, <<(pkt:igmp(Header))/binary, Payload/binary>>).
