-record(linux_cooked, {
        packet_type = ?DLT_LINUX_SLL :: pkt:uint16_t(),
        hrd = ?ARPHRD_ETHER :: pkt:uint16_t(),
        ll_len = 0 :: pkt:uint16_t(),
        ll_bytes = <<0,0,0,0,0,0,0,0>> :: <<_:64>>,
        pro = ?ETH_P_IP :: pkt:uint16_t()
    }).
