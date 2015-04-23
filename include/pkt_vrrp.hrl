-record(vrrp, {
    version = 2 :: pkt:bit4(),
    type = 1 :: pkt:bit4(),
    vrid = 1 :: 1..255,
    priority = 100 :: 1..255,
    auth_type = 0 :: pkt:uint8_t(),
    adver_int = 1 :: pkt:uint8_t(),
    sum = 0 :: pkt:uint16_t(),
    ip_addresses = [] :: [pkt:in_addr()]
}).
