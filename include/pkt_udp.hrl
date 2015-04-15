-record(udp, {
        sport = 0 :: pkt:in_port_t(), dport = 0 :: pkt:in_port_t(), ulen = 8 :: pkt:uint16_t(), sum = 0 :: pkt:uint16_t()
    }).
