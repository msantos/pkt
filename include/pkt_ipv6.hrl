-record(ipv6, {
        v = 6, class = 0, flow = 0,
        len = 40, next = ?IPPROTO_TCP, hop = 0,
        saddr, daddr
    }).
