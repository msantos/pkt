-record('802.1q', {
    prio :: 0..2#111, %% Priority
    cfi = 0 :: 0 | 1, %% Canonical Format Indicator
    vid :: 0..4095, %% VLAN Identifier
    type :: pkt:uint16_t() %% ethertype for next header
}).
