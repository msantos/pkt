-record(igmp, {
        type = 0,
        code = 0,
        csum = 0,
        group
    }).


-record(igmp_group, {
  type = 0,
  addr,
  sources = [],
  aux = <<>>
  }).