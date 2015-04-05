%% RFC 2460: IPv6 Specification
-record(ipv6, {
        v = 6 :: pkt:nibble(), class = 0 :: byte(), flow = 0 :: 0 .. 2#11111111111111111111,
        len = 40 :: pkt:uint16_t(), next = ?IPPROTO_TCP :: byte(), hop = 0 :: byte(),
        saddr :: pkt:in6_addr(), daddr :: pkt:in6_addr()
    }).

% XXX fix naming

%% IPv6 Extension Headers
%%
%% RFC 6564: A Uniform Format for IPv6 Extension Headers

% Hop-by-Hop Options Header
-record(ipv6_hopopts, {
        next = ?IPPROTO_NONE :: byte(),
        len = 0 :: byte(),
        opt = <<>> :: binary()
    }).

-record(ipv6_routing, {
        next = ?IPPROTO_NONE :: byte(),
        len = 0 :: byte(),
        type = 0 :: byte(),
        left = 0 :: byte(),
        data = <<>> :: binary()
    }).

-record(ipv6_fragment, {
        next = ?IPPROTO_NONE :: byte(),
        res = 0 :: byte(),
        off = 0 :: 0 .. 2#1111111111111,
        res2 = 0 :: 0 .. 3,
        m = 0 :: pkt:bit(),
        id = 0 :: pkt:uint32_t()
    }).

-record(ipv6_dstopts, {
        next = ?IPPROTO_NONE,
        len = 0,
        opt = <<>>
    }).

-record(ipv6_ah, {
        next = ?IPPROTO_NONE :: byte(),
        len = 0 :: byte(),
        res = 0 :: pkt:uint16_t(),
        spi = 0 :: pkt:uint32_t(),
        seq = 0 :: pkt:uint32_t(),
        icv = <<>> :: binary()
    }).

-record(ipv6_esp, {
        spi = ?IPPROTO_NONE :: pkt:uint32_t(),
        seq = 0 :: pkt:uint32_t(),
        data = <<>> :: binary(),
        pad = <<>> :: binary(),
        padlen = 0 :: byte(),
        next = 0 :: byte(),
        icv = <<>> :: binary()
    }).
