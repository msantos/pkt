-record(ipv4, {
        v = 4 :: pkt:nibble(), hl = 5 :: pkt:nibble(), tos = 0 :: byte(), len = 20 :: pkt:uint16_t(),
        id = 0 :: pkt:uint16_t(), df = 0 :: pkt:bit(), mf = 0 :: pkt:bit(),
        off = 0 :: 0 .. 2#1111111111111, ttl = 64 :: byte(), p = ?IPPROTO_TCP :: byte(), sum = 0 :: pkt:uint16_t(),
        saddr = {127,0,0,1} :: pkt:in_addr(), daddr = {127,0,0,1} :: pkt:in_addr(),
        opt = <<>> :: binary()
    }).
