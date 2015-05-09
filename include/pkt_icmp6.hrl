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

-define(MLD_LISTENER_QUERY, 130).
-define(MLD_LISTENER_REPORT, 131).
-define(MLD_LISTENER_REPORTV2, 143).
-define(MLD_LISTENER_REDUCTION, 132).

-define(ND_ROUTER_SOLICIT, 133).
-define(ND_ROUTER_ADVERT, 134).
-define(ND_NEIGHBOR_SOLICIT, 135).
-define(ND_NEIGHBOR_ADVERT, 136).
-define(ND_REDIRECT, 137).

-record(icmp6, {
        type = ?ICMP6_ECHO_REQUEST :: pkt:uint8_t(), code = 0 :: pkt:uint8_t(), checksum = 0 :: pkt:uint16_t(),

        un = <<0:32>> :: <<_:32>>,
        pptr = 0 :: pkt:uint32_t(),
        mtu = 0 :: pkt:uint32_t(),
        id = 0 :: pkt:uint16_t(),
        seq = 0 :: pkt:uint16_t(),
        maxdelay = 0 :: pkt:uint16_t(),

        res = 0 :: pkt:uint16_t(), res2 = 0 :: pkt:uint16_t(),

        saddr :: pkt:in6_addr(),
        daddr :: pkt:in6_addr(),

        % router advertisement
        hop = 0 :: pkt:uint8_t(), m = 0 :: pkt:bit(), o = 0 :: pkt:bit(), lifetime = 0 :: pkt:uint16_t(), reach = 0 :: pkt:uint32_t(), retrans = 0 :: pkt:uint32_t(),

        % Neighbor Advertisement Message
        r = 0 :: pkt:bit(), s = 0 :: pkt:bit(),

        % Multicast Listener Discovery (MLD)
        % use daddr for the multicast address
        delay = 0 :: pkt:uint16_t()
    }).
