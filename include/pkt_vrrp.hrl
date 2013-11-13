-record(vrrp, {
    version = 2,
    type = 1,
    vrid = 1 :: 1..255,
    priority = 100 :: 1..255,
    auth_type = 0,
    adver_int = 1,
    sum = 0,
    ip_addresses = []
}).
