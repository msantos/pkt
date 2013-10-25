-define(IPPROTO_IP, 0).
-define(IPPROTO_ICMP, 1).
-define(IPPROTO_TCP, 6).
-define(IPPROTO_UDP, 17).
-define(IPPROTO_IPV6, 41).
-define(IPPROTO_GRE, 47).
-define(IPPROTO_ICMPV6, 58).
-define(IPPROTO_SCTP, 132).
-define(IPPROTO_RAW, 255).

% IPV6 extension headers
-define(IPPROTO_HOPOPTS, 0).    % IPv6 hop-by-hop options
-define(IPPROTO_ROUTING, 43).   % IPv6 routing header
-define(IPPROTO_FRAGMENT, 44).  % IPv6 fragmentation header
-define(IPPROTO_NONE, 59).      % IPv6 no next header
-define(IPPROTO_DSTOPTS, 60).   % IPv6 destination options
-define(IPPROTO_MH, 135).       % IPv6 mobility header
