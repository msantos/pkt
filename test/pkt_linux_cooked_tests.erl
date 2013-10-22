-module(pkt_linux_cooked_tests).

-include_lib("pkt/include/pkt.hrl").
-include_lib("eunit/include/eunit.hrl").

codec_test_() ->
    [
        decode(),
        encode()
    ].

packet() ->
    <<0,0,0,1,0,6,0,22,182,181,62,198,0,0,8,0,69,0,0,52,3,46,64,0,54,6,
      168,8,108,168,151,6,192,168,213,54,0,80,137,182,95,193,153,133,
      143,44,160,100,128,16,0,126,82,76,0,0,1,1,8,10,222,215,19,81,29,
      225,199,124>>.

decode() ->
    {Header, Payload} = pkt:linux_cooked(packet()),
    ?_assertEqual(
        {{linux_cooked,0,1,6,<<0,22,182,181,62,198,0,0>>,2048},
         <<69,0,0,52,3,46,64,0,54,6,168,8,108,168,151,6,192,168,
           213,54,0,80,137,182,95,193,153,133,143,44,160,100,128,
           16,0,126,82,76,0,0,1,1,8,10,222,215,19,81,29,225,199,
           124>>},
        {Header, Payload}
    ).

encode() ->
    Packet = packet(),
    {Header, Payload} = pkt:linux_cooked(Packet),
    ?_assertEqual(Packet, <<(pkt:linux_cooked(Header))/binary, Payload/binary>>).
