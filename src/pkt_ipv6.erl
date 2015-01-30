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
-module(pkt_ipv6).

%% RFC 2460: Internet Protocol, Version 6 (IPv6) Specification

-include("pkt_ipproto.hrl").
-include("pkt_ipv6.hrl").

-export([codec/1]).

codec(
    <<6:4, Class:8, Flow:20,
    Len:16, Next:8, Hop:8,
    SA1:16, SA2:16, SA3:16, SA4:16, SA5:16, SA6:16, SA7:16, SA8:16,
    DA1:16, DA2:16, DA3:16, DA4:16, DA5:16, DA6:16, DA7:16, DA8:16,
    Payload/binary>>
) ->
    {#ipv6{
        class = Class, flow = Flow,
        len = Len, next = Next, hop = Hop,
        saddr = {SA1, SA2, SA3, SA4, SA5, SA6, SA7, SA8},
        daddr = {DA1, DA2, DA3, DA4, DA5, DA6, DA7, DA8}
    }, Payload};
codec(#ipv6{
        class = Class, flow = Flow,
        len = Len, next = Next, hop = Hop,
        saddr = {SA1, SA2, SA3, SA4, SA5, SA6, SA7, SA8},
        daddr = {DA1, DA2, DA3, DA4, DA5, DA6, DA7, DA8}
    }) ->
    <<6:4, Class:8, Flow:20,
    Len:16, Next:8, Hop:8,
    SA1:16, SA2:16, SA3:16, SA4:16, SA5:16, SA6:16, SA7:16, SA8:16,
    DA1:16, DA2:16, DA3:16, DA4:16, DA5:16, DA6:16, DA7:16, DA8:16>>.
