%% RFC 2784 - Generic Routing Encapsulation (GRE)
-record(gre, {
        c = 0, res0 = 0, ver = 0,
        type = ?ETH_P_IP,
        chksum = <<>>, res1 = <<>>
    }).
