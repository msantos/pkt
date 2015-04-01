%% RFC 2784 - Generic Routing Encapsulation (GRE)
-record(gre, {
        c = 0 :: pkt:bit(), res0 = 0 :: 0..2#111111111111, ver = 0 :: 0..2#111,
        type = ?ETH_P_IP :: pkt:uint16_t(),
        chksum = 0 :: pkt:uint16_t(), res1 = 0 :: pkt:uint16_t()
    }).
