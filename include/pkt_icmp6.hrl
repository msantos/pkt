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

-record(icmp6, {
        type = ?ICMP6_ECHO_REQUEST, code = 0, checksum = 0,

        un = <<0:32>>,
        pptr = 0,
        mtu = 0,
        id = 0,
        seq = 0,
        maxdelay = 0
    }).
