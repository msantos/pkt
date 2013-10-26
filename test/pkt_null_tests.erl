-module(pkt_null_tests).

-include_lib("pkt/include/pkt.hrl").
-include_lib("eunit/include/eunit.hrl").

codec_test_() ->
    [
        decode(),
        encode()
    ].

packet() ->
    % http://pcapr.net/view/tyson.key/2009/8/0/8/BSDloopback-loop0.cap.html
    <<2,0,0,0,69,0,0,28,0,0,0,0,1,1,0,0,127,0,0,1,127,0,0,1,0,0,35,111,
      163,125,0,19>>.

decode() ->
    {Header, Payload} = pkt:null(packet()),
    ?_assertEqual(
        {{null,2},
         <<69,0,0,28,0,0,0,0,1,1,0,0,127,0,0,1,127,0,0,1,0,0,35,
           111,163,125,0,19>>},
        {Header, Payload}
    ).

encode() ->
    Packet = packet(),
    {Header, Payload} = pkt:null(Packet),
    ?_assertEqual(Packet, <<(pkt:null(Header))/binary, Payload/binary>>).
