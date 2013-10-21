%% From http://en.wikipedia.org/wiki/EtherType
-define(ETH_P_IP, 16#0800).
-define(ETH_P_ARP, 16#0806).
-define(ETH_P_IPV6, 16#86DD).
-define(ETH_P_ALL, 16#0300).

-record(ether, {
        dhost = <<0,0,0,0,0,0>>,
        shost = <<0,0,0,0,0,0>>,
        type = ?ETH_P_IP,
        crc = 0
    }).
