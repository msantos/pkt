%% Copyright (c) 2009-2022, Michael Santos <michael.santos@gmail.com>
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
-module(pkt_linux_cooked_v2).

-include("pkt_dlt.hrl").
-include("pkt_ether.hrl").
-include("pkt_arp.hrl").
-include("pkt_linux_cooked.hrl").

-export([codec/1]).

codec(<<Pro:16/big, MBZ:2/bytes, Ifi:32/big, Hrd:16/big,
        Ptype:8, Ll_len:8/big, Ll_hdr:8/bytes, Payload/binary>>) ->
    {#linux_cooked_v2{
        pro = Pro, mbz = MBZ, if_idx = Ifi,
        hrd = Hrd, packet_type = Ptype,
        ll_len = Ll_len, ll_bytes = Ll_hdr
       }, Payload};
codec(#linux_cooked_v2{
         pro = Pro, mbz = MBZ, if_idx = Ifi,
         hrd = Hrd, packet_type = Ptype,
         ll_len = Ll_len, ll_bytes = Ll_hdr
        }) ->
    <<Pro:16/big, MBZ:2/bytes, Ifi:32/big, Hrd:16/big,
      Ptype:16, Ll_len:8/big, Ll_hdr:8/bytes>>.
