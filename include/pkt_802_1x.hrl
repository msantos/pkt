%%%-------------------------------------------------------------------
%%% @author alex_shavelev
%%% @copyright (C) 2016, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 07. Jun 2016 4:41 PM
%%%-------------------------------------------------------------------
-author("alex_shavelev").

%% http://www.vocal.com/secure-communication/eapol-extensible-authentication-protocol-over-lan/

-record(eapol, {
  version :: <<_:8>>,
  type :: <<_:8>>,
  length :: <<_:16>>,
  body
}).