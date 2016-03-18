-module(pkt_sctp_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("pkt/include/pkt_sctp.hrl").
-include_lib("pcapfile/include/pcapfile.hrl").

sctp_payload(File) ->
    {ok, #pcap{records = Recs}} = pcapfile:read_file(filename:join(["test/sctp_data", File])),
    %% Skip Ethernet & IPv4
    #pcap_record{payload = <<_Skip:34/binary-unit:8, Data/binary>>} = hd(Recs),
    Data.

codec_test_() ->
    [
        init_chunk(),
        init_ack_chunk(),
        cookie_echo_chunk(),
        cookie_ack_chunk(),
        data_chunk(),
        sack_chunk(),
        heartbeat_chunk(),
        heartbeat_ack_chunk(),
        abort_chunk(),
        shutdown_chunk(),
        shutdown_ack_chunk(),
        shutdown_complete_chunk()
    ].

init_chunk() ->
    SCTP = #sctp{
        sport = 38001,
        dport = 2006,
        vtag = 0,
        sum = 0,
        chunks = [
            #sctp_chunk{
                type = 1,
                i = 0,u = 0,b = 0,e = 0,
                len = 56,
                payload = #sctp_chunk_init{
                    itag = 3314912159,a_rwnd = 1500,
                    outbound_streams = 5,inbound_streams = 65535,tsn = 19012793,
                    params = [
                        {address_types,[ipv4]},
                        {ipv4,{192,168,2,2}},
                        {ipv4,{192,168,1,102}},
                        {ipv4,{127,0,0,1}}
                    ]
                }
            }
        ]
    },
    Data = sctp_payload("init.pcap"),
    ?_assertEqual({SCTP, <<>>}, pkt:sctp(Data)).

init_ack_chunk() ->
    SCTP = #sctp{
        sport = 2006,
        dport = 38001,
        vtag = 3314912159,
        sum = 3113214697,
        chunks = [
            #sctp_chunk{
                type = 2,
                i = 0,u = 0,b = 0,e = 0,
                len = 60,
                payload = #sctp_chunk_init_ack{
                    itag = 346325327,
                    a_rwnd = 65536,outbound_streams = 10,inbound_streams = 5,
                    tsn = 1885860370,
                    params = [
                        {state_cookie,<<21,235,131,195,114,192>>},
                        {ipv4,{192,168,2,2}},
                        {ipv4,{192,168,1,102}},
                        {ipv4,{127,0,0,1}}
                    ]
                }
            }
        ]
    },
    Data = sctp_payload("init_ack.pcap"),
    ?_assertEqual({SCTP, <<>>}, pkt:sctp(Data)).

cookie_echo_chunk() ->
    SCTP = #sctp{
        sport = 38001,
        dport = 2006,
        vtag = 346325327,
        sum = 1432062984,
        chunks = [
            #sctp_chunk{
                type = 10,
                i = 0,u = 0,b = 0,e = 0,
                len = 5,
                payload = #sctp_chunk_cookie_echo{cookie = <<21,235,131,195,114>>}
            }
        ]
    },
    Data = sctp_payload("cookie_echo.pcap"),
    ?_assertEqual({SCTP, <<>>}, pkt:sctp(Data)).

cookie_ack_chunk() ->
    SCTP = #sctp{
        sport = 2006,
        dport = 38001,
        vtag = 3314912159,
        sum = 0,
        chunks = [
            #sctp_chunk{
                type = 11,
                i = 0,u = 0,b = 0,e = 0,
                len = 0,
                payload = #sctp_chunk_cookie_ack{}
            }
        ]
    },
    Data = sctp_payload("cookie_ack.pcap"),
    ?_assertEqual({SCTP, <<>>}, pkt:sctp(Data)).

data_chunk() ->
    SCTP = #sctp{
        sport = 38001,
        dport = 2006,
        vtag = 346325327,
        sum = 0,
        chunks = [
            #sctp_chunk{
                type = 0,
                i = 0,u = 0,b = 1,e = 1,
                len = 18,
                payload = #sctp_chunk_data{
                    tsn = 19012793,sid = 0,ssn = 0,
                    ppi = 0,data = <<"Test 0">>
                }
            }
        ]
    },
    Data = sctp_payload("data.pcap"),
    ?_assertEqual({SCTP, <<>>}, pkt:sctp(Data)).

sack_chunk() ->
    SCTP = #sctp{
        sport = 2006,
        dport = 38001,
        vtag = 3314912159,
        sum = 0,
        chunks = [
            #sctp_chunk{
                type = 3,
                i = 0,u = 0,b = 0,e = 0,
                len = 12,
                payload = #sctp_chunk_sack{
                    tsn_ack = 19012793,
                    a_rwnd = 65530,
                    number_gap_ack_blocks = 0, number_duplicate_tsn = 0,
                    gap_ack_blocks = [], duplicate_tsns = []
                }
            }
        ]
    },
    Data = sctp_payload("sack.pcap"),
    ?_assertEqual({SCTP, <<>>}, pkt:sctp(Data)).

heartbeat_chunk() ->
    SCTP = #sctp{
        sport = 38001,
        dport = 2006,
        vtag = 346325327,
        sum = 3432649193,
        chunks = [
            #sctp_chunk{
                type = 4,
                i = 0,u = 0,b = 0,e = 0,
                len = 9,
                payload = #sctp_chunk_heartbeat{type = 1,info = <<2,0,7,214,192>>}
            }
        ]
    },
    Data = sctp_payload("heartbeat.pcap"),
    ?_assertEqual({SCTP, <<>>}, pkt:sctp(Data)).

heartbeat_ack_chunk() ->
    SCTP = #sctp{
        sport = 2006,
        dport = 38001,
        vtag = 3314912159,
        sum = 220783544,
        chunks = [
            #sctp_chunk{
                type = 5,
                i = 0,u = 0,b = 0,e = 0,
                len = 9,
                payload = #sctp_chunk_heartbeat_ack{type = 1, info = <<2,0,7,214,192>>}
            }
        ]
    },
    Data = sctp_payload("heartbeat_ack.pcap"),
    ?_assertEqual({SCTP, <<>>}, pkt:sctp(Data)).

abort_chunk() ->
    SCTP = #sctp{
        sport = 38001,
        dport = 2006,
        vtag = 346325327,
        sum = 0,
        chunks = [
            #sctp_chunk{
                type = 6,
                i = 0,u = 0,b = 0,e = 0,
                len = 4,
                payload = #sctp_chunk_abort{
                    error_causes = [
                        #sctp_error_cause{
                            code = 12,
                            descr = "User Initiated Abort",
                            opts = [{abort_reason,<<>>}]
                        }
                    ]
                }
            }
        ]
    },
    Data = sctp_payload("abort.pcap"),
    ?_assertEqual({SCTP, <<>>}, pkt:sctp(Data)).

shutdown_chunk() ->
    SCTP = #sctp{
        sport = 52565,
        dport = 2006,
        vtag = 775466434,
        sum = 0,
        chunks = [
            #sctp_chunk{
                type = 7,
                i = 0,u = 0,b = 0,e = 0,
                len = 4,
                payload = #sctp_chunk_shutdown{tsn_ack = 3349662519}
            }
        ]
    },
    Data = sctp_payload("shutdown.pcap"),
    ?_assertEqual({SCTP, <<>>}, pkt:sctp(Data)).

shutdown_ack_chunk() ->
    SCTP = #sctp{
        sport = 2006,
        dport = 52565,
        vtag = 15739429,
        sum = 0,
        chunks = [
            #sctp_chunk{
                type = 8,
                i = 0,u = 0,b = 0,e = 0,
                len = 0,
                payload = #sctp_chunk_shutdown_ack{}
            }
        ]
    },
    Data = sctp_payload("shutdown_ack.pcap"),
    ?_assertEqual({SCTP, <<>>}, pkt:sctp(Data)).

shutdown_complete_chunk() ->
    SCTP = #sctp{
        sport = 52565,
        dport = 2006,
        vtag = 775466434,
        sum = 0,
        chunks = [
            #sctp_chunk{
                type = 14,
                i = 0,u = 0,b = 0,e = 0,
                len = 0,
                payload = #sctp_chunk_shutdown_complete{}
            }
        ]
    },
    Data = sctp_payload("shutdown_complete.pcap"),
    ?_assertEqual({SCTP, <<>>}, pkt:sctp(Data)).
