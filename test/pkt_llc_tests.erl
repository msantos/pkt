-module(pkt_llc_tests).

-include_lib("pkt/include/pkt.hrl").
-include_lib("eunit/include/eunit.hrl").

codec_test_() ->
    [
        decode(),
        encode()
    ].

packet() ->
    <<170,170,3,0,0,12,1,11>>.

decode() ->
    {Header, Payload} = pkt:llc(packet()),
    Result = #llc{
        dsap = 16#AA,
        ssap = 16#AA,
        control = 3,
        vendor = <<0, 0, 16#0C>>, % Cisco
        pid = 267 % PVSTP+
    },
    ?_assertEqual({Result, <<>>}, {Header, Payload}).

encode() ->
    Packet = packet(),
    {Header, Payload} = pkt:llc(Packet),
    ?_assertEqual(Packet, <<(pkt:llc(Header))/binary, Payload/binary>>).
