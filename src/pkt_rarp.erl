%% Copyright (c) 2009-2017, Michael Santos <michael.santos@gmail.com>
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
-module(pkt_rarp).

-include("pkt_ether.hrl").
-include("pkt_rarp.hrl").

-export([codec/1]).

codec(<<Hrd:16, Pro:16,
    Hln:8, Pln:8, Op:16,
    Sha:6/bytes,
    SA1:8, SA2:8, SA3:8, SA4:8,
    Tha:6/bytes,
    DA1:8, DA2:8, DA3:8, DA4:8,
    Payload/binary>>
) ->
    {#rarp{
        hrd = Hrd, pro = Pro,
        hln = Hln, pln = Pln, op = Op,
        sha = Sha,
        sip = {SA1,SA2,SA3,SA4},
        tha = Tha,
        tip = {DA1,DA2,DA3,DA4}
    }, Payload};
codec(#rarp{
        hrd = Hrd, pro = Pro,
        hln = Hln, pln = Pln, op = Op,
        sha = Sha,
        sip = {SA1,SA2,SA3,SA4},
        tha = Tha,
        tip = {DA1,DA2,DA3,DA4}
    }) ->
    <<Hrd:16, Pro:16,
    Hln:8, Pln:8, Op:16,
    Sha:6/bytes,
    SA1:8, SA2:8, SA3:8, SA4:8,
    Tha:6/bytes,
    DA1:8, DA2:8, DA3:8, DA4:8>>.
