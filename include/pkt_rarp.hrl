-ifndef(ARPHRD_ETHER).
-define(ARPHRD_ETHER, 1).
-endif.

-define(ARPOP_RREQUEST, 3).                 % RARP request
-define(ARPOP_RREPLY, 4).                   % RARP reply

-record(rarp, {
        hrd = ?ARPHRD_ETHER :: pkt:uint16_t(),
        pro = ?ETH_P_IP :: pkt:uint16_t(),
        hln = 6 :: pkt:uint8_t(),
        pln = 4 :: pkt:uint8_t(),
        op = ?ARPOP_RREPLY :: pkt:uint16_t(),

        sha = <<0,0,0,0,0,0>> :: <<_:48>>,
        sip = {127,0,0,1} :: pkt:in_addr(),

        tha = <<0,0,0,0,0,0>> :: <<_:48>>,
        tip = {127,0,0,1} :: pkt:in_addr()
    }).
