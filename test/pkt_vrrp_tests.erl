-module(pkt_vrrp_tests).

-include_lib("pkt/include/pkt.hrl").
-include_lib("eunit/include/eunit.hrl").

codec_test_() ->
    [
        decode(),
        encode()
    ].

packet() ->
    <<33,64,254,1,0,1,110,145,10,13,104,30,0,0,0,0,0,0,0,0>>.

decode() ->
    {Header, Payload} = pkt:vrrp(packet()),
    Result = #vrrp{
        version = 2,
        type = 1,
        vrid = 64,
        priority = 254,
        auth_type = 0,
        adver_int = 1,
        sum = 28305,
        ip_addresses = [{10,13,104,30}]
    },
    ?_assertEqual({Result, <<>>}, {Header, Payload}).

encode() ->
    Packet = packet(),
    {Header, Payload} = pkt:vrrp(Packet),
    ?_assertEqual(Packet, <<(pkt:vrrp(Header))/binary, Payload/binary>>).
