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
-module(pkt_vrrp).

-export([codec/1]).

-include("pkt_vrrp.hrl").

codec(<<Version:4, Type:4, VRID:8, Prio:8, CntIP:8, AuthType:8, AdverInt:8, Sum:16, Rest/binary>>) ->
    ASize = CntIP * 4,
    <<Addresses:ASize/binary, 0:64, Payload/binary>> = Rest, % 0:64 - Application Data {1,2}
    {#vrrp{
        version = Version,
        type = Type,
        vrid = VRID,
        priority = Prio,
        auth_type = AuthType,
        adver_int = AdverInt,
        sum = Sum,
        ip_addresses = [{A, B, C, D} || <<A:8, B:8, C:8, D:8>> <= Addresses]
    }, Payload};
codec(#vrrp{version = Version, type = Type, vrid = VRID, priority = Prio, auth_type = AuthType, adver_int = AdverInt, sum = Sum, ip_addresses = Addresses}) ->
    CntIP = length(Addresses),
    ASize = CntIP * 4,
    IPs = << <<A:8, B:8, C:8, D:8>> || {A, B, C, D} <- Addresses >>,
    <<Version:4, Type:4, VRID:8, Prio:8, CntIP:8, AuthType:8, AdverInt:8, Sum:16, IPs:ASize/binary, 0:64>>.
