%% Copyright (c) 2009-2015, Michael Santos <michael.santos@gmail.com>
%% All rights reserved.
%%
%% Redistribution and use in source and binary forms, with or without
%% modification, are permitted provided that the following conditions
%% are met:
%%
%% Redistributions of source code must retain the above copyright
%% notice, this list of conditions and the following disclaimer.
%%
%% Redistributions in binary form must reproduce the above copyright
%% notice, this list of conditions and the following disclaimer in the
%% documentation and/or other materials provided with the distribution.
%%
%% Neither the name of the author nor the names of its contributors
%% may be used to endorse or promote products derived from this software
%% without specific prior written permission.
%%
%% THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
%% "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
%% LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
%% FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
%% COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
%% INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
%% BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
%% LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
%% CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
%% LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
%% ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
%% POSSIBILITY OF SUCH DAMAGE.
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
