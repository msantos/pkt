-module(pkt_rarp_tests).

-include_lib("pkt/include/pkt.hrl").
-include_lib("eunit/include/eunit.hrl").

codec_test_() ->
    [
        decode(),
        encode()
    ].

packet() ->
    <<16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#00, 16#23,
      16#20, 16#a8, 16#84, 16#c2, 16#80, 16#35, 16#00, 16#01,
      16#08, 16#00, 16#06, 16#04, 16#00, 16#03, 16#00, 16#23,
      16#20, 16#a8, 16#84, 16#c2, 16#00, 16#00, 16#00, 16#00,
      16#00, 16#23, 16#20, 16#a8, 16#84, 16#c2, 16#00, 16#00,
      16#00, 16#00>>.

decode() ->
    [_Ether, RArp, <<>>] = pkt:decapsulate(packet()),
    ?_assertEqual(
       {rarp,1,2048,6,4,3,
        <<0,35,32,168,132,194>>,
        {0,0,0,0},
        <<0,35,32,168,132,194>>,
        {0,0,0,0}},
        RArp
    ).

encode() ->
    <<_Ether:14/bytes, Packet/bytes>> = packet(),
    {Header, Payload} = pkt:rarp(Packet),
    ?_assertEqual(Packet, <<(pkt:rarp(Header))/binary, Payload/binary>>).
