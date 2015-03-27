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
        hrd = ?ARPHRD_ETHER :: pkt:uint16_t(),
        pro = ?ETH_P_IP :: pkt:uint16_t(),
        hln = 6 :: byte(),
        pln = 4 :: byte(),
        op = ?ARPOP_REPLY :: pkt:uint16_t(),

        sha = <<0,0,0,0,0,0>> :: <<_:48>>,
        sip = {127,0,0,1} :: pkt:in_addr(),

        tha = <<0,0,0,0,0,0>> :: <<_:48>>,
        tip = {127,0,0,1} :: pkt:in_addr()
    }).
