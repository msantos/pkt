-module(pkt_tests).

-include_lib("pkt/include/pkt.hrl").
-include_lib("eunit/include/eunit.hrl").

pkt_test_() ->
    [
        decapsulate_1(),
        decapsulate_2(),
        decapsulate_2_failure(),
        decapsulate_2_unsupported(),
        decode_1(),
        decode_2(),
        decode_2_failure(),
        decode_2_unsupported(),
        encode_1(),
        encode_2(),
        makesum_1(),
        makesum_2(),
        makesum_4(),
        makesum_8(),
        makesum_16(),
        makesum_32(),
        makesum_64()
    ].

packet(ether) ->
    <<224,105,149,59,163,24,0,22,182,181,62,198,8,0,69,0,0,54,2,108,64,
      0,53,6,172,243,173,192,82,195,192,168,213,54,0,80,143,166,75,154,
      212,181,116,33,53,92,128,24,0,126,60,199,0,0,1,1,8,10,92,104,96,
      16,22,69,237,136,137,0>>;
packet(tcp) ->
    <<0,80,217,184,222,13,22,43,241,75,9,12,176,18,17,4,140,86,
      0,0,2,4,5,172,1, 3,3,0,1,1,8,10,190,15,172,236,0,64,161,73,4,2,0,0>>;
packet(ipv4_hdr) ->
    <<69,0,0,54,2,108,64,0,53,6,172,243,173,192,82,195,192,
        168,213,54>>.

decapsulate_1() ->
    ?_assertEqual(
        [{ether,<<224,105,149,59,163,24>>,
                <<0,22,182,181,62,198>>,
                2048,0},
         {ipv4,4,5,0,54,620,1,0,0,53,6,44275,
               {173,192,82,195},
               {192,168,213,54},
               <<>>},
         {tcp,80,36774,1268438197,1948333404,8,0,0,0,0,1,1,0,0,0,126,
              15559,0,
              <<1,1,8,10,92,104,96,16,22,69,237,136>>},
         <<137,0>>],
        pkt:decapsulate(packet(ether))
    ).

decapsulate_2() ->
    ?_assertEqual(
        [{tcp,80,55736,3725399595,4048226572,11,0,0,0,0,1,0,0,1,0,
              4356,35926,0,
              <<2,4,5,172,1,3,3,0,1,1,8,10,190,15,172,236,0,64,161,73,
                4,2,0,0>>},
              <<>>],
        pkt:decapsulate(tcp, packet(tcp))
    ).

decapsulate_2_failure() ->
    ?_assertException(
        error,
        function_clause,
        pkt:decapsulate(ipv6, packet(tcp))
    ).

decapsulate_2_unsupported() ->
    ?_assertException(
        error,
        function_clause,
        pkt:decapsulate(ether, packet(tcp))
    ).

decode_1() ->
    ?_assertEqual(
        {ok,{[{ether,<<224,105,149,59,163,24>>,
                     <<0,22,182,181,62,198>>,
                       2048,0},
              {ipv4,4,5,0,54,620,1,0,0,53,6,44275,
                    {173,192,82,195},
                    {192,168,213,54},
                    <<>>},
              {tcp,80,36774,1268438197,1948333404,8,0,0,0,0,1,1,0,0,0,126,
                   15559,0,
                   <<1,1,8,10,92,104,96,16,22,69,237,136>>}],
              <<137,0>>}},
        pkt:decode(packet(ether))
    ).

decode_2() ->
    ?_assertEqual(
        {ok,{[{tcp,80,55736,3725399595,4048226572,11,0,0,0,0,1,0,0,1,0,
                   4356,35926,0,
                   <<2,4,5,172,1,3,3,0,1,1,8,10,190,15,172,236,0,64,161,73,
                     4,2,0,0>>}],
               <<>>}},
        pkt:decode(tcp, packet(tcp))
    ).

decode_2_failure() ->
    ?_assertEqual(
        {error,[],
               {ipv6,<<0,80,217,184,222,13,22,43,241,75,9,12,176,18,17,
                       4,140,86,0,0,2,4,5,172,1,3,3,0,1,1,8,10,190,15,
                       172,236,0,64,161,73,4,2,0,0>>}},
        pkt:decode(ipv6, packet(tcp))
    ).

decode_2_unsupported() ->
    ?_assertEqual(
        {error,[{ether,<<0,80,217,184,222,13>>,
                       <<22,43,241,75,9,12>>,
                       45074,0}],
                {unsupported,<<17,4,140,86,0,0,2,4,5,172,1,3,3,0,1,1,8,
                               10,190,15,172,236,0,64,161,73,4,2,0,0>>}},
        pkt:decode(ether, packet(tcp))
    ).

encode_1() -> [
    ?_assertEqual(
        packet(ether),
        pkt:encode(pkt:decapsulate(packet(ether)))
    ),
    ?_assertNotEqual(
        packet(ether),
        pkt:encode({pkt:decapsulate(packet(ether)), <<0,2>>})
    )
].

encode_2() -> [
    ?_assertEqual(
        packet(ipv4_hdr),
        pkt:encode(pkt:ipv4(packet(ipv4_hdr)))
    ),
    ?_assertNotEqual(
        packet(ipv4_hdr),
        pkt:encode({pkt:ipv4(packet(ipv4_hdr)), <<0,1>>})
    )
].

makesum_1() ->
    ?_assertEqual(
        3839,
        pkt:makesum(<<16#F1>>)
    ).

makesum_2() ->
    ?_assertEqual(
        3597,
        pkt:makesum(<<16#F1, 16#F2>>)
    ).

makesum_4() ->
    ?_assertEqual(
        6680,
        pkt:makesum(<<16#F1, 16#F2, 16#F3, 16#F4>>)
    ).

makesum_8() ->
    ?_assertEqual(
        11304,
        pkt:makesum(<<16#F1, 16#F2, 16#F3, 16#F4, 16#F5, 16#F6, 16#F7, 16#F8>>)
    ).

makesum_16() ->
    ?_assertEqual(
        22608,
        pkt:makesum(<<16#F1, 16#F2, 16#F3, 16#F4, 16#F5, 16#F6, 16#F7, 16#F8, 16#F1, 16#F2, 16#F3, 16#F4, 16#F5, 16#F6, 16#F7, 16#F8>>)
    ).


makesum_32() ->
    ?_assertEqual(
        45216,
        pkt:makesum(<<16#F1, 16#F2, 16#F3, 16#F4, 16#F5, 16#F6, 16#F7, 16#F8, 16#F1, 16#F2, 16#F3, 16#F4, 16#F5, 16#F6, 16#F7, 16#F8, 16#F1, 16#F2, 16#F3, 16#F4, 16#F5, 16#F6, 16#F7, 16#F8, 16#F1, 16#F2, 16#F3, 16#F4, 16#F5, 16#F6, 16#F7, 16#F8 >>)
    ).

makesum_64() ->
    ?_assertEqual(
        24897,
        pkt:makesum(<<16#F1, 16#F2, 16#F3, 16#F4, 16#F5, 16#F6, 16#F7, 16#F8, 16#F1, 16#F2, 16#F3, 16#F4, 16#F5, 16#F6, 16#F7, 16#F8, 16#F1, 16#F2, 16#F3, 16#F4, 16#F5, 16#F6, 16#F7, 16#F8, 16#F1, 16#F2, 16#F3, 16#F4, 16#F5, 16#F6, 16#F7, 16#F8, 16#F1, 16#F2, 16#F3, 16#F4, 16#F5, 16#F6, 16#F7, 16#F8, 16#F1, 16#F2, 16#F3, 16#F4, 16#F5, 16#F6, 16#F7, 16#F8, 16#F1, 16#F2, 16#F3, 16#F4, 16#F5, 16#F6, 16#F7, 16#F8, 16#F1, 16#F2, 16#F3, 16#F4, 16#F5, 16#F6, 16#F7, 16#F8>>)
    ).
