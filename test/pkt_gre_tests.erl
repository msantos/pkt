-module(pkt_gre_tests).

-include_lib("pkt/include/pkt.hrl").
-include_lib("eunit/include/eunit.hrl").

codec_test_() ->
    [
        decode(),
        encode()
    ].

packet() ->
    <<255,0,8,0,119,128,0,0,69,0,0,35,148,47,0,0,64,1,238,215,
      127,0,0,1,127,0,0,1,8,0,165,38,217,147,0,1>>.

decode() ->
    {Header, Payload} = pkt:gre(packet()),
    ?_assertEqual(
        {{gre,1,4064,0,2048,30592,0},
         <<69,0,0,35,148,47,0,0,64,1,238,215,127,0,0,1,127,0,0,1,
           8,0,165,38,217,147,0,1>>},
        {Header, Payload}
    ).

encode() ->
    Packet = packet(),
    {Header, Payload} = pkt:gre(Packet),
    ?_assertEqual(Packet, <<(pkt:gre(Header))/binary, Payload/binary>>).
