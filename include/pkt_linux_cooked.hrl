-record(linux_cooked, {
        packet_type = ?DLT_LINUX_SLL :: pkt:uint16_t(),
        hrd = ?ARPHRD_ETHER :: pkt:uint16_t(),
        ll_len = 0 :: pkt:uint16_t(),
        ll_bytes = <<0,0,0,0,0,0,0,0>> :: <<_:64>>,
        pro = ?ETH_P_IP :: pkt:uint16_t()
    }).

-record(linux_cooked_v2, {
         pro = ?ETH_P_IP :: pkt:uint16_t(),
         mbz = <<0,0>> :: <<_:16>>,
         if_idx = 1 :: pkt:uint32_t(),
         hrd = ?ARPHRD_ETHER :: pkt:uint16_t(),
         packet_type = ?DLT_LINUX_SLL2 :: pkt:uint16_t(),
         ll_len = 0 :: pkt:uint16_t(),
         ll_bytes = <<0,0,0,0,0,0,0,0>> :: <<_:64>>
    }).
