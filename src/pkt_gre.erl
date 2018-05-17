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
-module(pkt_gre).

-include("pkt_ether.hrl").
-include("pkt_gre.hrl").

-export([codec/1]).

codec(<<C:1,R:1,K:1,S:1,Res0:9,Ver:3,Type:16,Bin/binary>>) ->
  {[Chksum, Res1, Key, Sequence], Payload} = unpack([C, K, S], Bin),
  {#gre{c = C, r = R, k = K, s = S, res0 = Res0, ver = Ver, type = Type, chksum = Chksum,
    res1 = Res1, key = Key, sequence = Sequence
       },Payload
    };

codec(#gre{c = C, r = R, k = K, s = S, res0 = Res0, ver = Ver, type = Type, chksum = Chksum,
    res1 = Res1, key = Key, sequence = Sequence
       }) ->
    ChecksumLength = C*16,
    Res1Length = ChecksumLength,
    KeyLength = K*32,
    SequenceLength = S*32,
    <<C:1,R:1,K:1,S:1,Res0:9,Ver:3,Type:16,Chksum:ChecksumLength,Res1:Res1Length,Key:KeyLength,Sequence:SequenceLength>>.

unpack([0, 0, 0], Bin) -> {[0, 0, 0, 0], Bin};
unpack([C, K, S], Bin) ->
  ChecksumLength = C*16,
  Res1Length = ChecksumLength,
  KeyLength = K*32,
  SequenceLength = S*32,
  <<Chksum:ChecksumLength,Res1:Res1Length,Key:KeyLength,Sequence:SequenceLength,Payload/binary>> = Bin,
  {[Chksum, Res1, Key, Sequence], Payload}.