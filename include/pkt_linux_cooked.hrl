-record(linux_cooked, {
	packet_type,
	hrd = ?ARPHRD_ETHER,
	ll_len = 0,
	ll_bytes = <<>>,
	pro = ?ETH_P_IP
    }).
