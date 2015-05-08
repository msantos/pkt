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

-record(icmp, {
        type = ?ICMP_ECHO :: pkt:uint8_t(), code = 0 :: pkt:uint8_t(), checksum = 0 :: pkt:uint16_t(),
        id = 0 :: pkt:uint16_t(), sequence = 0 :: pkt:uint16_t(),
        gateway = {127,0,0,1} :: pkt:in_addr(),
        un = <<0:32>> :: binary(),
        mtu = 0 :: pkt:uint16_t(),
        pointer = 0 :: pkt:uint8_t(),
        ts_orig = 0 :: pkt:uint32_t(), ts_recv = 0 :: pkt:uint32_t(), ts_tx = 0 :: pkt:uint32_t()
    }).
