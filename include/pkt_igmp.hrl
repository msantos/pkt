-record(igmp_group, {
  type = 0,
  addr,
  sources = [],
  aux = <<>>
  }).

-record(igmp, {
        type = 0 :: byte(),
        code = 0 :: byte(),
        csum = 0 :: pkt:uint16_t(),
        group :: pkt:in_addr() | [#igmp_group{}]
    }).
