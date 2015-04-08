-record(igmp_group, {
  type = 0,
  addr,
  sources = [],
  aux = <<>>
  }).

-record(igmp, {
        type = 0 :: pkt:uint8_t(),
        code = 0 :: pkt:uint8_t(),
        csum = 0 :: pkt:uint16_t(),
        group :: pkt:in_addr() | [#igmp_group{}]
    }).
