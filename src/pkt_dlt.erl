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
-module(pkt_dlt).

-include("pkt_dlt.hrl").

-export([codec/1]).

%%
%% Datalink types
%%
codec(?DLT_NULL) -> null;
codec(?DLT_EN10MB) -> en10mb;
codec(?DLT_EN3MB) -> en3mb;
codec(?DLT_AX25) -> ax25;
codec(?DLT_PRONET) -> pronet;
codec(?DLT_CHAOS) -> chaos;
codec(?DLT_IEEE802) -> ieee802;
codec(?DLT_ARCNET) -> arcnet;
codec(?DLT_SLIP) -> slip;
codec(?DLT_PPP) -> ppp;
codec(?DLT_FDDI) -> fddi;
codec(?DLT_ATM_RFC1483) -> atm_rfc1483;
codec(?DLT_RAW) -> raw;
codec(?DLT_SLIP_BSDOS) -> slip_bsdos;
codec(?DLT_PPP_BSDOS) -> ppp_bsdos;
codec(?DLT_PFSYNC) -> pfsync;
codec(?DLT_ATM_CLIP) -> atm_clip;
codec(?DLT_PPP_SERIAL) -> ppp_serial;
%dlt(?DLT_C_HDLC) -> c_hdlc;
codec(?DLT_CHDLC) -> chdlc;
codec(?DLT_IEEE802_11) -> ieee802_11;
codec(?DLT_LOOP) -> loop;
codec(?DLT_LINUX_SLL) -> linux_sll;
codec(?DLT_PFLOG) -> pflog;
codec(?DLT_IEEE802_11_RADIO) -> ieee802_11_radio;
codec(?DLT_APPLE_IP_OVER_IEEE1394) -> apple_ip_over_ieee1394;
codec(?DLT_IEEE802_11_RADIO_AVS) -> ieee802_11_radio_avs;
codec(?DLT_LINUX_SLL2) -> linux_sll2;

codec(null) -> ?DLT_NULL;
codec(en10mb) -> ?DLT_EN10MB;
codec(en3mb) -> ?DLT_EN3MB;
codec(ax25) -> ?DLT_AX25;
codec(pronet) -> ?DLT_PRONET;
codec(chaos) -> ?DLT_CHAOS;
codec(ieee802) -> ?DLT_IEEE802;
codec(arcnet) -> ?DLT_ARCNET;
codec(slip) -> ?DLT_SLIP;
codec(ppp) -> ?DLT_PPP;
codec(fddi) -> ?DLT_FDDI;
codec(atm_rfc1483) -> ?DLT_ATM_RFC1483;
codec(raw) -> ?DLT_RAW;
codec(slip_bsdos) -> ?DLT_SLIP_BSDOS;
codec(ppp_bsdos) -> ?DLT_PPP_BSDOS;
codec(pfsync) -> ?DLT_PFSYNC;
codec(atm_clip) -> ?DLT_ATM_CLIP;
codec(ppp_serial) -> ?DLT_PPP_SERIAL;
codec(c_hdlc) -> ?DLT_C_HDLC;
codec(chdlc) -> ?DLT_CHDLC;
codec(ieee802_11) -> ?DLT_IEEE802_11;
codec(loop) -> ?DLT_LOOP;
codec(linux_sll) -> ?DLT_LINUX_SLL;
codec(pflog) -> ?DLT_PFLOG;
codec(ieee802_11_radio) -> ?DLT_IEEE802_11_RADIO;
codec(apple_ip_over_ieee1394) -> ?DLT_APPLE_IP_OVER_IEEE1394;
codec(ieee802_22_radio_avs) -> ?DLT_IEEE802_11_RADIO_AVS;
codec(linux_sll2) -> ?DLT_LINUX_SLL2.
