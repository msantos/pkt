-module(pkt_ipproto_tests).

-include_lib("pkt/include/pkt.hrl").
-include_lib("eunit/include/eunit.hrl").

codec_test_() ->
    [
        encode(),
        decode(),
        encode_fail()
    ].

encode() ->
    ?_assertEqual(ipv6_hopopts, pkt_ipproto:codec(?IPPROTO_HOPOPTS)).

decode() ->
    ?_assertEqual(?IPPROTO_HOPOPTS, pkt_ipproto:codec(ipv6_hopopts)).

encode_fail() ->
    ?_assertException(
        error,
        function_clause,
        pkt_ipproto:codec(31337)
    ).
