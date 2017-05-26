-define(IPV4_PROTO_TCP, 6).

-record(ipv4, {
        v = 4 :: pkt:bit4(), hl = 5 :: pkt:bit4(), tos = 0 :: pkt:uint8_t(), len = 20 :: pkt:uint16_t(),
        id = 0 :: pkt:uint16_t(), df = 0 :: pkt:bit(), mf = 0 :: pkt:bit(),
        off = 0 :: 0 .. 2#1111111111111, ttl = 64 :: pkt:uint8_t(), p = ?IPV4_PROTO_TCP :: pkt:uint8_t(), sum = 0 :: pkt:uint16_t(),
        saddr = {127,0,0,1} :: pkt:in_addr(), daddr = {127,0,0,1} :: pkt:in_addr(),
        opt = <<>> :: binary()
    }).
