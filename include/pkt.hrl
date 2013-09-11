%% From http://en.wikipedia.org/wiki/EtherType
-define(ETH_P_IP, 16#0800).
-define(ETH_P_ARP, 16#0806).
-define(ETH_P_IPV6, 16#86DD).
-define(ETH_P_ALL, 16#0300).

-define(ARPHRD_ETHER, 1).
-define(ARPHRD_IEEE80211, 801).

-define(ARPOP_REQUEST, 1).                  % ARP request
-define(ARPOP_REPLY, 2).                    % ARP reply
-define(ARPOP_RREQUEST, 3).                 % RARP request
-define(ARPOP_RREPLY, 4).                   % RARP reply
-define(ARPOP_InREQUEST, 8).                % InARP request
-define(ARPOP_InREPLY, 9).                  % InARP reply
-define(ARPOP_NAK, 10).                     % (ATM)ARP NAK

%% Datalink types
-define(DLT_NULL, 0).                       % BSD loopback
-define(DLT_EN10MB, 1).                     % Ethernet
-define(DLT_LINUX_SLL, 113).                % Linux cooked sockets fake hdr
-define(DLT_EN3MB, 2).
-define(DLT_AX25, 3).
-define(DLT_PRONET, 4).
-define(DLT_CHAOS, 5).
-define(DLT_IEEE802, 6).
-define(DLT_ARCNET, 7).
-define(DLT_SLIP, 8).
-define(DLT_PPP, 9).
-define(DLT_FDDI, 10).
-define(DLT_ATM_RFC1483, 11).
-define(DLT_RAW, 12).
-define(DLT_SLIP_BSDOS, 15).
-define(DLT_PPP_BSDOS, 16).
-define(DLT_PFSYNC, 18).
-define(DLT_ATM_CLIP, 19).
-define(DLT_PPP_SERIAL, 50).
-define(DLT_C_HDLC, 104).
-define(DLT_CHDLC, ?DLT_C_HDLC).
-define(DLT_IEEE802_11, 105).
-define(DLT_LOOP, 108).
-define(DLT_PFLOG, 117).
-define(DLT_IEEE802_11_RADIO, 127).
-define(DLT_APPLE_IP_OVER_IEEE1394, 138).
-define(DLT_IEEE802_11_RADIO_AVS, 163).

-ifndef(PF_UNSPEC).
-define(PF_UNSPEC,0).                       % Unspecified.
-endif.
-ifndef(PF_LOCAL).
-define(PF_LOCAL, 1).                       % Local to host (pipes and file-domain).
-endif.
-ifndef(PF_UNIX).
-define(PF_UNIX, ?PF_LOCAL).                % POSIX name for PF_LOCAL.
-endif.
-ifndef(PF_INET).
-define(PF_INET, 2).                        % IP protocol family.
-endif.
-ifndef(PF_INET6).
-define(PF_INET6, 10).                      % IP version 6.
-endif.
-ifndef(PF_PACKET).
-define(PF_PACKET, 17).                     % Packet family.
-endif.

-define(IPPROTO_IP, 0).
-define(IPPROTO_ICMP, 1).
-define(IPPROTO_TCP, 6).
-define(IPPROTO_UDP, 17).
-define(IPPROTO_IPV6, 41).
-define(IPPROTO_GRE, 47).
-define(IPPROTO_ICMPV6, 58).
-define(IPPROTO_SCTP, 132).
-define(IPPROTO_RAW, 255).

-define(ICMP_ECHOREPLY, 0).
-define(ICMP_DEST_UNREACH, 3).
-define(    ICMP_UNREACH_NET, 0).           % bad net
-define(    ICMP_UNREACH_HOST, 1).          % bad host
-define(    ICMP_UNREACH_PROTOCOL, 2).      % bad protocol
-define(    ICMP_UNREACH_PORT, 3).          % bad port
-define(    ICMP_UNREACH_NEEDFRAG, 4).      % IP_DF caused drop
-define(    ICMP_UNREACH_SRCFAIL, 5 ).      % src route failed
-define(ICMP_SOURCE_QUENCH, 4).
-define(ICMP_REDIRECT, 5).
-define(    ICMP_REDIRECT_NET, 0).          % for network
-define(    ICMP_REDIRECT_HOST, 1).         % for host
-define(    ICMP_REDIRECT_TOSNET, 2).       % for tos and net
-define(    ICMP_REDIRECT_TOSHOST, 3).      % for tos and host
-define(ICMP_ECHO, 8).
-define(ICMP_TIME_EXCEEDED, 11).
-define(    ICMP_TIMXCEED_INTRANS, 0).      % ttl==0 in transit
-define(    ICMP_TIMXCEED_REASS, 1).        % ttl==0 in reass
-define(ICMP_PARAMETERPROB, 12).
-define(ICMP_TIMESTAMP, 13).
-define(ICMP_TIMESTAMPREPLY, 14).
-define(ICMP_INFO_REQUEST, 15).
-define(ICMP_INFO_REPLY, 16).
-define(ICMP_ADDRESS, 17).
-define(ICMP_ADDRESSREPLY, 18).

-define(ICMP6_DST_UNREACH, 1).
-define(ICMP6_PACKET_TOO_BIG, 2).
-define(ICMP6_TIME_EXCEEDED, 3).
-define(ICMP6_PARAM_PROB, 4).
-define(ICMP6_INFOMSG_MASK, 16#80).         % all informational messages
-define(ICMP6_ECHO_REQUEST, 128).
-define(ICMP6_ECHO_REPLY, 129).
-define(ICMP6_DST_UNREACH_NOROUTE, 0).      % no route to destination
-define(ICMP6_DST_UNREACH_ADMIN, 1).        % communication with destination
-define(ICMP6_DST_UNREACH_BEYONDSCOPE, 2).  % beyond scope of source address
-define(ICMP6_DST_UNREACH_ADDR, 3).         % address unreachable
-define(ICMP6_DST_UNREACH_NOPORT, 4).       % bad port
-define(ICMP6_TIME_EXCEED_TRANSIT, 0).      % Hop Limit == 0 in transit
-define(ICMP6_TIME_EXCEED_REASSEMBLY, 1).   % Reassembly time out
-define(ICMP6_PARAMPROB_HEADER, 0).         % erroneous header field
-define(ICMP6_PARAMPROB_NEXTHEADER, 1).     % unrecognized Next Header
-define(ICMP6_PARAMPROB_OPTION, 2).         % unrecognized IPv6 option
-define(ICMP6_ROUTER_RENUMBERING, 138).

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

-record(linux_cooked, {
	packet_type,
	hrd = ?ARPHRD_ETHER,
	ll_len = 0,
	ll_bytes = <<>>,
	pro = ?ETH_P_IP
    }).

-record(null, {
        family = ?PF_INET
    }).

-record(ether, {
        dhost = <<0,0,0,0,0,0>>,
        shost = <<0,0,0,0,0,0>>,
        type = ?ETH_P_IP,
        crc = 0
    }).

-record(arp, {
        hrd = ?ARPHRD_ETHER,
        pro = ?ETH_P_IP,
        hln = 6,
        pln = 4,
        op = ?ARPOP_REPLY,

        sha = <<0,0,0,0,0,0>>,
        sip = {127,0,0,1},

        tha = <<0,0,0,0,0,0>>,
        tip = {127,0,0,1}
    }).

-record(ipv4, {
        v = 4, hl = 5, tos = 0, len = 20,
        id = 0, df = 0, mf = 0,
        off = 0, ttl = 64, p = ?IPPROTO_TCP, sum = 0,
        saddr = {127,0,0,1}, daddr = {127,0,0,1},
        opt = <<>>
    }).

-record(ipv6, {
        v = 6, class = 0, flow = 0,
        len = 40, next = ?IPPROTO_TCP, hop = 0,
        saddr, daddr
    }).

-record(tcp, {
        sport = 0, dport = 0,
        seqno = 0,
        ackno = 0,
        off = 5, cwr = 0, ece = 0, urg = 0, ack = 0,
        psh = 0, rst = 0, syn = 0, fin = 0, win = 0,
        sum = 0, urp = 0,
        opt = <<>>
    }).

-record(udp, {
        sport = 0, dport = 0, ulen = 8, sum = 0
    }).

-record(icmp, {
        type = ?ICMP_ECHO, code = 0, checksum = 0,
        id = 0, sequence = 0,
        gateway = {127,0,0,1},
        un = <<0:32>>,
        mtu = 0,
        pointer = 0,
        ts_orig = 0, ts_recv = 0, ts_tx = 0
    }).

-record(icmp6, {
        type = ?ICMP6_ECHO_REQUEST, code = 0, checksum = 0,

        un = <<0:32>>,
        pptr = 0,
        mtu = 0,
        id = 0,
        seq = 0,
        maxdelay = 0
    }).

-record(sctp, {
    sport = 0, dport = 0, vtag = 0, sum = 0,
    chunks = []
}).

-record(sctp_chunk, {
    type = 0, flags = 0, len = 0, payload = 0
}).

-record(sctp_chunk_data, {
    tsn = 0, sid = 0, ssn = 0, ppi = 0, data
}).

-record(sctp_chunk_init, {
    itag :: pos_integer(),
    a_rwnd :: non_neg_integer(),
    outbound_streams :: pos_integer(),
    inbound_streams :: pos_integer(),
    tsn :: non_neg_integer(),
    params  = [] :: [proplists:property()]
}).

-record(sctp_chunk_init_ack, {
    itag :: pos_integer(),
    a_rwnd :: non_neg_integer(),
    outbound_streams :: pos_integer(),
    inbound_streams :: pos_integer(),
    tsn :: non_neg_integer(),
    params  = [] :: [proplists:property()]
}).

-record(sctp_chunk_cookie_echo, {
    cookie
}).

-record(sctp_chunk_heartbeat, {
    type = 1, info
}).

-record(sctp_chunk_heartbeat_ack, {
    type = 1, info
}).

%% RFC 2784 - Generic Routing Encapsulation (GRE)
-record(gre, {
        c = 0, res0 = 0, ver = 0,
        type = ?ETH_P_IP,
        chksum = <<>>, res1 = <<>>
    }).
