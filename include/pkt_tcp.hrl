-record(tcp, {
        sport = 0 :: pkt:in_port_t(), dport = 0 :: pkt:in_port_t(),
        seqno = 0 :: pkt:uint32_t(),
        ackno = 0 :: pkt:uint32_t(),
        off = 5 :: pkt:nibble(), cwr = 0 :: 0 | 1, ece = 0 :: 0 | 1, urg = 0 :: 0 | 1, ack = 0 :: 0 | 1,
        psh = 0 :: 0 | 1, rst = 0 :: 0 | 1, syn = 0 :: 0 | 1, fin = 0 :: 0 | 1, win = 0 :: pkt:uint16_t(),
        sum = 0 :: pkt:uint16_t(), urp = 0 :: pkt:uint16_t(),
        opt = <<>> :: binary()
    }).
