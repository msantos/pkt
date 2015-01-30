%% Copyright (c) 2013-2015, Michael Santos <michael.santos@gmail.com>
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
-module(pkt_ipproto).

-include("pkt_ipproto.hrl").

-export([codec/1]).

% IPPROTO_HOPOPTS and IPROTO_IP are both defined as 0
%codec(?IPPROTO_IP) -> ip;
codec(?IPPROTO_ICMP) -> icmp;
codec(?IPPROTO_IGMP) -> igmp;
codec(?IPPROTO_ICMPV6) -> icmp6;
codec(?IPPROTO_TCP) -> tcp;
codec(?IPPROTO_UDP) -> udp;
codec(?IPPROTO_IPV6) -> ipv6;
codec(?IPPROTO_VRRP) -> vrrp;
codec(?IPPROTO_SCTP) -> sctp;
codec(?IPPROTO_GRE) -> gre;
codec(?IPPROTO_RAW) -> raw;

codec(?IPPROTO_HOPOPTS) -> ipv6_hopopts;
codec(?IPPROTO_ROUTING) -> ipv6_routing;
codec(?IPPROTO_FRAGMENT) -> ipv6_fragment;
codec(?IPPROTO_NONE) -> ipv6_none;
codec(?IPPROTO_DSTOPTS) -> ipv6_dstopts;
codec(?IPPROTO_MH) -> ipv6_mh;

codec(ip) -> ?IPPROTO_IP;
codec(icmp) -> ?IPPROTO_ICMP;
codec(igmp) -> ?IPPROTO_IGMP;
codec(icmp6) -> ?IPPROTO_ICMPV6;
codec(tcp) -> ?IPPROTO_TCP;
codec(udp) -> ?IPPROTO_UDP;
codec(ipv6) -> ?IPPROTO_IPV6;
codec(vrrp) -> ?IPPROTO_VRRP;
codec(sctp) -> ?IPPROTO_SCTP;
codec(gre) -> ?IPPROTO_GRE;

codec(ipv6_hopopts) -> ?IPPROTO_HOPOPTS;
codec(ipv6_routing) -> ?IPPROTO_ROUTING;
codec(ipv6_fragment) -> ?IPPROTO_FRAGMENT;
codec(ipv6_none) -> ?IPPROTO_NONE;
codec(ipv6_dstopts) -> ?IPPROTO_DSTOPTS ;
codec(ipv6_mh) -> ?IPPROTO_MH.
