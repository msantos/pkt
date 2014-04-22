-module(pkt_802_1q_tests).

-include_lib("pkt/include/pkt.hrl").
-include_lib("eunit/include/eunit.hrl").

codec_test_() ->
    [
        decode(),
        encode()
    ].

packet() -> <<1,84,8,0>>.

decode() ->
    {Header, Payload} = pkt:'802.1q'(packet()),
    Result = #'802.1q'{
        tpid = 340,
        prio = 0,
        cfi = 0,
        vid = 2048
    },
    ?_assertEqual({Result, <<>>}, {Header, Payload}).

encode() ->
    Packet = packet(),
    {Header, Payload} = pkt:'802.1q'(Packet),
    ?_assertEqual(Packet, <<(pkt:'802.1q'(Header))/binary, Payload/binary>>).
