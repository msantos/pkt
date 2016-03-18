-define(SCTP_CHUNK_DATA, 0).                % Payload data
-define(SCTP_CHUNK_INIT, 1).                % Initiation
-define(SCTP_CHUNK_INIT_ACK, 2).            % Initiation acknowledgement
-define(SCTP_CHUNK_SACK, 3).                % Selective acknowledgement
-define(SCTP_CHUNK_HEARTBEAT, 4).           % Heartbeat request
-define(SCTP_CHUNK_HEARTBEAT_ACK, 5).       % Heartbeat acknowledgement
-define(SCTP_CHUNK_ABORT, 6).               % Abort
-define(SCTP_CHUNK_SHUTDOWN, 7).            % Shutdown
-define(SCTP_CHUNK_SHUTDOWN_ACK, 8).        % Shutdown acknowledgement
-define(SCTP_CHUNK_ERROR, 9).               % Operation error
-define(SCTP_CHUNK_COOKIE_ECHO, 10).        % State cookie
-define(SCTP_CHUNK_COOKIE_ACK, 11).         % Cookie acknowledgement
-define(SCTP_CHUNK_SHUTDOWN_COMPLETE, 14).  % Shutdown complete

-record(sctp_chunk, {
    type = 0 :: 0..254, %% The value of 255 is reserved for future use as an extension field
    %% Flags
    i = 0 :: pkt:bit(),
    u = 0 :: pkt:bit(),
    b = 1 :: pkt:bit(),
    e = 0 :: pkt:bit(),
    %% End of flags
    len = 0 :: pkt:uint16_t(),
    payload = 0
}).

-record(sctp, {
    sport  = 0  :: inet:port_number(),
    dport  = 0  :: inet:port_number(),
    vtag   = 0  :: pkt:uint32_t(),
    sum    = 0  :: pkt:uint32_t(),
    chunks = [] :: [#sctp_chunk{}]
}).

-record(sctp_chunk_data, {
    tsn = 0 :: pkt:uint32_t(),
    sid = 0 :: pkt:uint16_t(),
    ssn = 0 :: pkt:uint16_t(),
    ppi = 0 :: pkt:uint32_t(),
    data = <<>> :: binary()
}).

-record(sctp_chunk_init, {
    itag = 0 :: pkt:uint32_t(),
    a_rwnd = 0 :: pkt:uint32_t(),
    outbound_streams = 0 :: pkt:uint16_t(),
    inbound_streams = 0 :: pkt:uint16_t(),
    tsn = 0 :: pkt:uint32_t(),
    params = [] :: [proplists:property()]
}).

-record(sctp_chunk_init_ack, {
    itag = 0 :: pkt:uint32_t(),
    a_rwnd = 0 :: pkt:uint32_t(),
    outbound_streams = 0 :: pkt:uint16_t(),
    inbound_streams = 0 :: pkt:uint16_t(),
    tsn = 0 :: pkt:uint32_t(),
    params  = [] :: [proplists:property()]
}).

-record(sctp_chunk_sack, {
    tsn_ack = 0 :: pkt:uint32_t(),
    a_rwnd = 0 :: pkt:uint32_t(),
    number_gap_ack_blocks = 0 :: pkt:uint16_t(),
    number_duplicate_tsn = 0 :: pkt:uint16_t(),
    gap_ack_blocks = [] :: [{pkt:uint16_t(), pkt:uint16_t()}],
    duplicate_tsns = [] :: [pkt:uint32_t()]
}).

-record(sctp_chunk_cookie_echo, {
    cookie :: binary()
}).

-record(sctp_chunk_cookie_ack, {}).

-record(sctp_chunk_heartbeat, {
    type = 1 :: 1,
    info = <<>> :: binary()
}).

-record(sctp_chunk_heartbeat_ack, {
    type = 1 :: 1,
    info = <<>> :: binary()
}).

-record(sctp_chunk_shutdown, {
    tsn_ack = 0 :: pkt:uint32_t()
}).

-record(sctp_chunk_shutdown_ack, {}).
-record(sctp_chunk_shutdown_complete, {}).

-record(sctp_error_cause, {
    code :: 1..13,
    descr :: string(),
    opts = [] :: [proplists:property()]
}).

-record(sctp_chunk_abort, {
    error_causes = [] :: [#sctp_error_cause{}]
}).
