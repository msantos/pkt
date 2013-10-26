-module(pkt_dlt_tests).

-include_lib("pkt/include/pkt.hrl").
-include_lib("eunit/include/eunit.hrl").

codec_test_() ->
    [
        encode(),
        decode(),
        encode_fail()
    ].

encode() ->
    ?_assertEqual(ieee802_11, pkt_dlt:codec(?DLT_IEEE802_11)).

decode() ->
    ?_assertEqual(?DLT_IEEE802_11, pkt_dlt:codec(ieee802_11)).

encode_fail() ->
    ?_assertException(
        error,
        function_clause,
        pkt_dlt:codec(31337)
    ).
