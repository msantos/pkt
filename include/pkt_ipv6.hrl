-define(IPV6_PROTO_TCP, 6).

%% RFC 2460: IPv6 Specification
-record(ipv6, {
        v = 6 :: pkt:bit4(), class = 0 :: pkt:uint8_t(), flow = 0 :: 0 .. 2#11111111111111111111,
        len = 40 :: pkt:uint16_t(), next = ?IPV6_PROTO_TCP :: pkt:uint8_t(), hop = 0 :: pkt:uint8_t(),
        saddr :: pkt:in6_addr(), daddr :: pkt:in6_addr()
    }).

% XXX fix naming

%% IPv6 Extension Headers
%%
%% RFC 6564: A Uniform Format for IPv6 Extension Headers

% Hop-by-Hop Options Header
-record(ipv6_hopopts, {
        next = ?IPPROTO_NONE :: pkt:uint8_t(),
        len = 0 :: pkt:uint8_t(),
        opt = <<>> :: binary()
    }).

-record(ipv6_routing, {
        next = ?IPPROTO_NONE :: pkt:uint8_t(),
        len = 0 :: pkt:uint8_t(),
        type = 0 :: pkt:uint8_t(),
        left = 0 :: pkt:uint8_t(),
        data = <<>> :: binary()
    }).

-record(ipv6_fragment, {
        next = ?IPPROTO_NONE :: pkt:uint8_t(),
        res = 0 :: pkt:uint8_t(),
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
        next = ?IPPROTO_NONE :: pkt:uint8_t(),
        len = 0 :: pkt:uint8_t(),
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
        padlen = 0 :: pkt:uint8_t(),
        next = 0 :: pkt:uint8_t(),
        icv = <<>> :: binary()
    }).
