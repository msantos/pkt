-define(ARPHRD_ETHER, 1).
-define(ARPHRD_IEEE80211, 801).

-define(ARPOP_REQUEST, 1).                  % ARP request
-define(ARPOP_REPLY, 2).                    % ARP reply
-define(ARPOP_RREQUEST, 3).                 % RARP request
-define(ARPOP_RREPLY, 4).                   % RARP reply
-define(ARPOP_InREQUEST, 8).                % InARP request
-define(ARPOP_InREPLY, 9).                  % InARP reply
-define(ARPOP_NAK, 10).                     % (ATM)ARP NAK

-record(arp, {
        hrd = ?ARPHRD_ETHER,
        pro = ?ETH_P_IP,
        hln = 6,
        pln = 4,
        op = ?ARPOP_REPLY,

        sha = <<0,0,0,0,0,0>>,
        sip = {127,0,0,1},

        tha = <<0,0,0,0,0,0>>,
        tip = {127,0,0,1}
    }).
