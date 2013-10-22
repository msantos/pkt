-module(pkt_icmp_tests).

-include_lib("pkt/include/pkt.hrl").
-include_lib("eunit/include/eunit.hrl").

codec_test_() ->
    [
        decode(),
        encode()
    ].

packet() ->
    <<0,0,147,214,5,65,0,1,113,241,102,82,0,0,0,0,198,208,9,
      0,0,0,0,0,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,
      31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,
      49,50,51,52,53,54,55>>.

decode() ->
    {Header, Payload} = pkt:icmp(packet()),
    ?_assertEqual(
        {{icmp,0,0,37846,1345,1,{127,0,0,1},<<0,0,0,0>>,0,0,0,0,0},
         <<113,241,102,82,0,0,0,0,198,208,9,0,0,0,0,0,16,17,18,19,
           20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,
           38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55>>},
        {Header, Payload}
    ).

encode() ->
    Packet = packet(),
    {Header, Payload} = pkt:icmp(Packet),
    ?_assertEqual(Packet, <<(pkt:icmp(Header))/binary, Payload/binary>>).
