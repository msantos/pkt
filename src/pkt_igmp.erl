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
-module(pkt_igmp).

-include("pkt_igmp.hrl").

-export([codec/1]).


% IGMPv3 message, http://tools.ietf.org/html/rfc3376#page-12
codec(<<Type:8, _:8, Checksum:16, _:16, GroupCount:16, Bin/binary>>) when Type == 16#22 ->
    {Groups, Payload} = unpack_groups(GroupCount, Bin),
    {#igmp{
        type = Type, csum = Checksum,
        group = Groups
    }, Payload};

% IGMPv2 messages
codec(<<Type:8, Code:8, Checksum:16,
    DA1:8, DA2:8, DA3:8, DA4:8, Payload/binary>>) ->
    {#igmp{
        type = Type, code = Code, csum = Checksum,
        group = {DA1,DA2,DA3,DA4}
    }, Payload};

codec(#igmp{
        type = Type, csum = Checksum,
        group = Groups
    }) when Type == 16#22 andalso is_list(Groups) ->
    GroupBin = [pack_group(Group) || Group <- Groups],
    iolist_to_binary([<<Type:8, 0:8, Checksum:16, 0:16, (length(Groups)):16>>, GroupBin]);

codec(#igmp{
        type = Type, code = Code, csum = Checksum,
        group = {DA1,DA2,DA3,DA4}
    }) ->
    <<Type:8, Code:8, Checksum:16, DA1:8, DA2:8, DA3:8, DA4:8>>.



unpack_groups(0, Bin) -> {[], Bin};
unpack_groups(Count, <<Type, Len, SourceCount:16, I1,I2,I3,I4, Bin/binary>>) ->
  SourceLength = SourceCount*4,
  <<SourceBin:SourceLength/binary, Aux:Len/binary, Rest/binary>> = Bin,
  Sources = [{S1,S2,S3,S4} || <<S1,S2,S3,S4>> <= SourceBin],
  {Groups, Payload} = unpack_groups(Count - 1, Rest),
  {[#igmp_group{type = Type, addr = {I1,I2,I3,I4}, sources = Sources, aux = Aux}|Groups], Payload}.


pack_group(#igmp_group{type = Type, aux = Aux, addr = {I1,I2,I3,I4}, sources = Sources}) ->
  SourcesBin = [<<S1,S2,S3,S4>> || {S1,S2,S3,S4} <- Sources],
  [<<Type, (size(Aux)), (length(Sources)):16, I1,I2,I3,I4>>, SourcesBin, Aux].

