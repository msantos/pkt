-module(pkt_tests).

-include("pkt.hrl").
-include("pkt_tests.hrl").
-include_lib("eunit/include/eunit.hrl").

sctp_test() ->
    {SCTP, []} = pkt:sctp(?SCTP_PACKET),
    {SCTP1, []} = pkt:sctp(?SCTP_PACKET_WITH_PADDING),
    Chunk = erlang:hd(SCTP#sctp.chunks),
    Chunk1 = erlang:hd(SCTP1#sctp.chunks),
    ?assertEqual(SCTP#sctp.sport, 7),
    ?assertEqual(SCTP1#sctp.dport, 32837),
    ?assertEqual(Chunk#sctp_chunk.type, 1),
    ?assertEqual(byte_size(Chunk#sctp_chunk.payload), 28),
    ?assertEqual(length(SCTP1#sctp.chunks), 1),
    ?assertEqual(Chunk1#sctp_chunk.payload#sctp_chunk_data.tsn, 2860946939).
