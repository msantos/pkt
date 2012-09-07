-module(pkt_tests).

-include("pkt.hrl").
-include("pkt_tests.hrl").
-include_lib("eunit/include/eunit.hrl").

sctp_test() ->
    {SCTP, []} = pkt:sctp(?SCTP_PACKET),
    Chunk = erlang:hd(SCTP#sctp.chunks),
    ?assertEqual(length(SCTP#sctp.chunks), 1),
    ?assertEqual(Chunk#sctp_chunk.payload#sctp_chunk_data.tsn, 2860946939).
