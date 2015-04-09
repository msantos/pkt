-record(llc, {
    dsap = 16#AA :: pkt:uint8_t(), % Destination Service Access Point
    ssap = 16#AA :: pkt:uint8_t(), % Source Service Access Point
    control = 16#03 :: pkt:uint8_t(),
    %% SNAP (Sub-Network Access Protocol) fields
    vendor = <<0, 0, 0>> :: <<_:24>>,
    pid = 0 :: pkt:uint16_t() % Ethertype for the frame
}).
