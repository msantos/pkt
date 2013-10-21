-record(ipv4, {
        v = 4, hl = 5, tos = 0, len = 20,
        id = 0, df = 0, mf = 0,
        off = 0, ttl = 64, p = ?IPPROTO_TCP, sum = 0,
        saddr = {127,0,0,1}, daddr = {127,0,0,1},
        opt = <<>>
    }).
