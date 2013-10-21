-record(tcp, {
        sport = 0, dport = 0,
        seqno = 0,
        ackno = 0,
        off = 5, cwr = 0, ece = 0, urg = 0, ack = 0,
        psh = 0, rst = 0, syn = 0, fin = 0, win = 0,
        sum = 0, urp = 0,
        opt = <<>>
    }).
