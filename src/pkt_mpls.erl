-module(pkt_mpls).

-include("pkt_mpls.hrl").

-export([codec/1]).

codec(Mpls) when is_binary(Mpls) ->
    decode(Mpls, []);
codec(#mpls{labels = Labels}) ->
    encode(Labels, <<>>).

decode(<<L:20, Tc:3, 1:1, Ttl:8, Rest/binary>>, Labels0) ->
    Mpls = #shim{label = L, tc = Tc, s = true, ttl = Ttl},
    Labels = #mpls{labels = lists:reverse([Mpls|Labels0])},
    {Next, Payload} = next_header(Rest),
    {Labels, Next, Payload};
decode(<<L:20, Tc:3, 0:1, Ttl:8, Rest/binary>>, Labels0) ->
    Mpls = #shim{label = L, tc = Tc, s = false, ttl = Ttl},
    decode(Rest, [Mpls|Labels0]).

encode([], Bin) -> Bin;
encode([#shim{label = L, tc = Tc, s = true, ttl = Ttl}|_], Bin) ->
    <<Bin/bytes, L:20, Tc:3, 1:1, Ttl:8>>;
encode([#shim{label = L, tc = Tc, s = false, ttl = Ttl}|Rest], Bin) ->
    encode(Rest, <<L:20, Tc:3, 0:1, Ttl:8, Bin/bytes>>).

next_header(<<>>) -> {none, <<>>};
next_header(<<4:4, _/bitstring>> = Binary) -> {ipv4, Binary};
next_header(<<6:4, _/bitstring>> = Binary) -> {ipv6, Binary}.
