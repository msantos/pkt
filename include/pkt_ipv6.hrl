%% RFC 2460: IPv6 Specification
-record(ipv6, {
        v = 6, class = 0, flow = 0,
        len = 40, next = ?IPPROTO_TCP, hop = 0,
        saddr, daddr
    }).

% XXX fix naming

%% IPv6 Extension Headers
%%
%% RFC 6564: A Uniform Format for IPv6 Extension Headers

% Hop-by-Hop Options Header
-record(ipv6_hopopts, {
        next = ?IPPROTO_NONE,
        len = 0,
        opt = <<>>
    }).

-record(ipv6_routing, {
        next = ?IPPROTO_NONE,
        len = 0,
        type = 0,
        left = 0,
        data = <<>>
    }).

-record(ipv6_fragment, {
        next = ?IPPROTO_NONE,
        res = 0,
        off = 0,
        res2 = 0,
        m = 0,
        id = <<>>
    }).

-record(ipv6_dstopts, {
        next = ?IPPROTO_NONE,
        len = 0,
        opt = <<>>
    }).

-record(ipv6_ah, {
        next = ?IPPROTO_NONE,
        len = 0,
        res = 0,
        spi = 0,
        seq = 0,
        icv = <<>>
    }).

-record(ipv6_esp, {
        spi = ?IPPROTO_NONE,
        seq = 0,
        data = <<>>,
        pad = <<>>,
        padlen = 0,
        next = 0,
        icv = <<>>
    }).
