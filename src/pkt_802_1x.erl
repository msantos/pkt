%%%-------------------------------------------------------------------
%%% @author alex_shavelev
%%% @copyright (C) 2016, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 07. Jun 2016 4:43 PM
%%%-------------------------------------------------------------------
-module(pkt_802_1x).
-author("alex_shavelev").

-include("pkt_802_1x.hrl").

%% API
-export([
  codec/1
]).

codec(<<Version:8, Type:8, Length:16, Body:Length/bytes, Rest/binary>>) ->
  {#eapol{
    version = Version,
    type = Type,
    length = Length,
    body = Body
  }, Rest};

codec(#eapol{version = Version, type = Type, length = Length, body = Body}) ->
  <<Version:8, Type:8, Length:16, Body:Length/bytes>>.
