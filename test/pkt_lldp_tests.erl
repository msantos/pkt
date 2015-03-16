-module(pkt_lldp_tests).

-include_lib("pkt/include/pkt.hrl").
-include_lib("eunit/include/eunit.hrl").

codec_test_() ->
    [
        decode(),
        encode()
    ].

packet() ->
    <<16#02, 16#09, 16#07, 16#00, 16#00, 16#00, 16#00, 16#00,
      16#00, 16#01, 16#23, 16#04, 16#05, 16#07, 16#00, 16#00,
      16#00, 16#0c, 16#06, 16#02, 16#00, 16#78, 16#00, 16#00,
      16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00,
      16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00,
      16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00,
      16#00, 16#00>>.

decode() ->
    ?_assertEqual({ #lldp{pdus = [#chassis_id{subtype = locally_assigned,
                                              value = <<0,0,0,0,0,0,1,35>>},
                                  #port_id{subtype = locally_assigned,
                                           value = <<0,0,0,12>>},
                                  #ttl{value = 120},
                                  #end_of_lldpdu{}]}, <<>> },
                  pkt:lldp(packet())).

encode() ->
    {Header, _Payload} = pkt:lldp(packet()),
    ?_assertEqual(pkt_lldp:codec(Header), packet()).
