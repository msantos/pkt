-module(pkt_tests).

-include("pkt.hrl").
-include("pkt_tests.hrl").
-include_lib("eunit/include/eunit.hrl").

-define(SCTP_DATA_FILE(File), filename:join(["../test/sctp_data/", File])).

sctp_test_() ->
    [
        sctp_init_chunk(),
        sctp_init_ack_chunk(),
        sctp_cookie_echo_chunk(),
        sctp_cookie_ack_chunk(),
        sctp_data_chunk(),
        sctp_sack_chunk(),
        sctp_heartbeat_chunk(),
        sctp_heartbeat_ack_chunk(),
        sctp_abort_chunk(),
        sctp_shutdown_chunk(),
        sctp_shutdown_ack_chunk(),
        sctp_shutdown_complete_chunk()
    ].

sctp_init_chunk() ->
    {ok, Data} = file:read_file(?SCTP_DATA_FILE("init.raw")),
    Result = {
        #sctp{
            sport = 59724,dport = 2006,vtag = 0,sum = 1614594302,chunks = [
                #sctp_chunk{type = 1,flags = 0,len = 48,payload =
                    #sctp_chunk_init{
                        itag = 2970287606,a_rwnd = 1500,outbound_streams = 5,
                        inbound_streams = 65535,tsn = 2961831077, params = [
                            {address_type,ipv4},
                            {ipv4,{192,168,1,100}},
                            {ipv4,{127,0,0,1}}
                        ]
                    }
                }
            ]
        }, []
    },
    ?_assertEqual(Result, pkt:sctp(Data)).

sctp_init_ack_chunk() ->
    {ok, Data} = file:read_file(?SCTP_DATA_FILE("init_ack.raw")),
    Result = {
        #sctp{
            sport = 2006,dport = 59724,vtag = 2970287606,sum = 2902204350,chunks = [
                #sctp_chunk{type = 2,flags = 0,len = 408,payload =
                    #sctp_chunk_init_ack{
                        itag = 3211144336,a_rwnd = 65536,outbound_streams = 10,
                        inbound_streams = 5,tsn = 321265112,params = [
                            {state_cookie, ?SCTP_INIT_ACK_STATE_COOKIE},
                            {ipv6,{65152,0,0,0,543,50943,65027,38823}},
                            {ipv4,{192,168,1,100}},
                            {ipv6,{0,0,0,0,0,0,0,1}},
                            {ipv4,{127,0,0,1}}
                        ]
                    }
                }
            ]
        }, []
    },
    ?_assertEqual(Result, pkt:sctp(Data)).

sctp_cookie_echo_chunk() ->
    {ok, Data} = file:read_file(?SCTP_DATA_FILE("cookie_echo.raw")),
    Result = {
        #sctp{
            sport = 59724,dport = 2006,vtag = 3211144336,sum = 3598540682,chunks = [
                #sctp_chunk{type = 10,flags = 0,len = 324,payload =
                    #sctp_chunk_cookie_echo{cookie = ?SCTP_INIT_ACK_STATE_COOKIE}
                }
            ]
        }, []
    },
    ?_assertEqual(Result, pkt:sctp(Data)).

sctp_cookie_ack_chunk() ->
    {ok, Data} = file:read_file(?SCTP_DATA_FILE("cookie_ack.raw")),
    Result = {
        #sctp{
            sport = 2006,dport = 59724,vtag = 2970287606,sum = 3517160060,chunks = [
                #sctp_chunk{type = 11,flags = 0,len = 0,payload = #sctp_chunk_cookie_ack{}}
            ]
        }, []
    },
    ?_assertEqual(Result, pkt:sctp(Data)).

sctp_data_chunk() ->
    {ok, Data} = file:read_file(?SCTP_DATA_FILE("data.raw")),
    Result = {
        #sctp{
            sport = 59724,dport = 2006,vtag = 3211144336,sum = 1694899720,chunks = [
                #sctp_chunk{type = 0,flags = 3,len = 18,payload =
                    #sctp_chunk_data{tsn = 2961831077,sid = 0,ssn = 0,ppi = 0,data = <<"Test 0">>}
                }
            ]
        }, []
    },
    ?_assertEqual(Result, pkt:sctp(Data)).

sctp_sack_chunk() ->
    {ok, Data} = file:read_file(?SCTP_DATA_FILE("sack.raw")),
    Result = {
        #sctp{
            sport = 2927,dport = 2927,vtag = 1909763671,sum = 2589260046,chunks = [
                #sctp_chunk{type = 3,flags = 0,len = 20,payload =
                    #sctp_chunk_sack{
                        tsn_ack = 1893031318,a_rwnd = 1240320,
                        number_gap_ack_blocks = 0,number_duplicate_tsn = 2,
                        gap_ack_blocks = [],
                        duplicate_tsns = [1893031317,1893031318]
                    }
                }
            ]
        }, []
    },
    ?_assertEqual(Result, pkt:sctp(Data)).

sctp_heartbeat_chunk() ->
    {ok, Data} = file:read_file(?SCTP_DATA_FILE("heartbeat.raw")),
    Result = {
        #sctp{
            sport = 59724,dport = 2006,vtag = 3211144336,sum = 1607855905,chunks = [
                #sctp_chunk{type = 4,flags = 0,len = 48,payload =
                    #sctp_chunk_heartbeat{type = 1,info = ?SCTP_HEARTBEAT_INFO}
                }
            ]
        }, []
    },
    ?_assertEqual(Result, pkt:sctp(Data)).

sctp_heartbeat_ack_chunk() ->
    {ok, Data} = file:read_file(?SCTP_DATA_FILE("heartbeat_ack.raw")),
    Result = {
        #sctp{
            sport = 2006,dport = 59724,vtag = 2970287606,sum = 4192969679,chunks = [
                #sctp_chunk{type = 5,flags = 0,len = 48,payload =
                    #sctp_chunk_heartbeat_ack{type = 1,info = ?SCTP_HEARTBEAT_INFO}
                }
            ]
        }, []
    },
    ?_assertEqual(Result, pkt:sctp(Data)).

sctp_abort_chunk() ->
    {ok, Data} = file:read_file(?SCTP_DATA_FILE("abort.raw")),
    Result = {
        #sctp{
            sport = 59724,dport = 2006,vtag = 3211144336,sum = 80506190,chunks = [
                #sctp_chunk{type = 6,flags = 0,len = 4,payload =
                    #sctp_chunk_abort{error_causes = [
                        #sctp_error_cause{code = 12,descr = "User Initiated Abort",opts = [
                            {abort_reason,<<>>}
                        ]}
                    ]}
                }]
        }, []
    },
    ?_assertEqual(Result, pkt:sctp(Data)).

sctp_shutdown_chunk() ->
    {ok, Data} = file:read_file(?SCTP_DATA_FILE("shutdown.raw")),
    Result = {
        #sctp{
            sport = 44282,dport = 2006,vtag = 3894864518,sum = 3455106587,chunks = [
                #sctp_chunk{type = 7,flags = 0,len = 4,payload =
                    #sctp_chunk_shutdown{tsn_ack = 430357211}
                }
            ]
        }, []
    },
    ?_assertEqual(Result, pkt:sctp(Data)).

sctp_shutdown_ack_chunk() ->
    {ok, Data} = file:read_file(?SCTP_DATA_FILE("shutdown_ack.raw")),
    Result = {
        #sctp{
            sport = 2006,dport = 44282,vtag = 1619613099,sum = 3544315687,chunks = [
                #sctp_chunk{type = 8,flags = 0,len = 0,payload = #sctp_chunk_shutdown_ack{}}
            ]
        }, []
    },
    ?_assertEqual(Result, pkt:sctp(Data)).

sctp_shutdown_complete_chunk() ->
    {ok, Data} = file:read_file(?SCTP_DATA_FILE("shutdown_complete.raw")),
    Result = {
        #sctp{
            sport = 44282,dport = 2006,vtag = 3894864518,sum = 2141610842,chunks = [
                #sctp_chunk{type = 14,flags = 0,len = 0,payload = #sctp_chunk_shutdown_complete{}}
            ]
        }, []
    },
    ?_assertEqual(Result, pkt:sctp(Data)).
