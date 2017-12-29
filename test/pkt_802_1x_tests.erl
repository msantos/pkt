-module(pkt_802_1x_tests).

-include_lib("pkt/include/pkt.hrl").
-include_lib("eunit/include/eunit.hrl").

codec_test_() ->
    [
        decode(),
        encode()
    ].

packet() ->
    <<208,231,130,187,173,120,216,80,230,215,165,93,136,142,2,3,0,127,2,19,
      130,0,0,0,0,0,0,0,0,0,4,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,48,35,21,192,82,245,73,203,215,177,67,166,119,19,51,
      133,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,200,45,182,0,54,207,185,135,165,160,
      10,70,95,175,108,147,0,32,112,46,203,250,45,160,87,202,238,37,17,167,64,
      202,98,8,201,119,185,73,11,98,90,123,40,181,73,189,189,89,19,137>>.

decode() ->
    [_Ether, EAPoL, _Payload] = pkt:decapsulate(packet()),
    ?_assertEqual(
       {'802.1x',2, 3, 127 },
       EAPoL
    ).

encode() ->
    <<_Ether:14/bytes, Packet/bytes>> = packet(),
    {Header, Payload} = pkt:'802.1x'(Packet),
    ?_assertEqual(Packet, <<(pkt:'802.1x'(Header))/binary, Payload/binary>>).
