-module(pkt_ipv4_tests).

-include_lib("pkt/include/pkt.hrl").
-include_lib("eunit/include/eunit.hrl").

codec_test_() ->
    [
        decode(),
        encode()
    ].

packet() ->
    <<69,0,0,54,2,108,64,0,53,6,172,243,173,192,82,195,192,
      168,213,54,0,80,143,166,75,154,212,181,116,33,53,92,128,
      24,0,126,60,199,0,0,1,1,8,10,92,104,96,16,22,69,237,136,
      137,0>>.

decode() ->
    {Header, Payload} = pkt:ipv4(packet()),
    ?_assertEqual(
        {{ipv4,4,5,0,54,620,1,0,0,53,6,44275,
         {173,192,82,195},
         {192,168,213,54},
         <<>>},
         <<0,80,143,166,75,154,212,181,116,33,53,92,128,24,0,126,
           60,199,0,0,1,1,8,10,92,104,96,16,22,69,237,136,137,0>>},
         {Header, Payload}
    ).

encode() ->
    Packet = packet(),
    {Header, Payload} = pkt:ipv4(Packet),
    ?_assertEqual(Packet, <<(pkt:ipv4(Header))/binary, Payload/binary>>).
