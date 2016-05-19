%% Copyright (c) 2009-2016, Michael Santos <michael.santos@gmail.com>
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

%% IEEE 802.1Q, 802.1ad (802.1q QinQ)
-module(pkt_802_1q).

-include("pkt_802_1q.hrl").

-export([codec/1]).

% See: https://en.wikipedia.org/wiki/IEEE_802.1ad
%
% The 802.1q 4-byte tag is inserted into the frame between the source
% MAC and the original tag:
%
%   Original frame:
%       <<Dhost:6/bytes, Shost:6/bytes, EtherType:16, Payload/binary>>
%
%   With 802.1q tag:
%       <<Dhost:6/bytes, Shost:6/bytes,
%           16#81, 16#00, Prio:3, CFI:1, VID:12,
%           EtherType:16, Payload/binary>>
%
%   802.1ad (802.1QinQ) tag:
%       <<Dhost:6/bytes, Shost:6/bytes,
%           16#88, 16#a8, Prio:3, CFI:1, VID:12,
%           16#81, 16#00, Prio:3, CFI:1, VID:12,
%           EtherType:16, Payload/binary>>
%
% The original ethernet type tag is replaced with the 802.1q TPID. The
% inner 802.1q header (tag 2 or C-TAG) is set to the original ethertype.
%
codec(<<Prio:3, CFI:1, VID:12, Type:16, Payload/binary>>) ->
    {#'802.1q'{
        prio = Prio,
        cfi = CFI,
        vid = VID,
        type = Type
    }, Payload};
codec(#'802.1q'{prio = Prio, cfi = CFI, vid = VID, type = Type}) ->
    <<Prio:3, CFI:1, VID:12, Type:16>>.
