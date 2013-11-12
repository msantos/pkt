-record(llc, {
    dsap = 16#AA, % Destination Service Access Point
    ssap = 16#AA, % Source Service Access Point
    control = 16#03,
    %% SNAP (Sub-Network Access Protocol) fields
    vendor = <<0, 0, 0>>,
    pid = 0 % Ethertype for the frame
}).
