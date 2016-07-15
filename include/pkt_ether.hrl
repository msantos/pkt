%% From http://en.wikipedia.org/wiki/EtherType
-define(ETH_P_IP, 16#0800).
-define(ETH_P_ARP, 16#0806).
-define(ETH_P_IPV6, 16#86DD).
-define(ETH_P_802_1Q, 16#8100).
-define(ETH_P_802_1QinQ, 16#88a8).
-define(ETH_P_LLDP, 16#88CC).
-define(ETH_P_MPLS_UNI, 16#8847).
-define(ETH_P_MPLS_MULTI, 16#8848).

-record(ether, {
    dhost = <<0,0,0,0,0,0>> :: <<_:48>>,
    shost = <<0,0,0,0,0,0>> :: <<_:48>>,
    type = ?ETH_P_IP :: pkt:uint16_t(),
    crc = 0 :: pkt:bit4()
}).
