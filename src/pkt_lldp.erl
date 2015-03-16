-module(pkt_lldp).

-include("pkt_ether.hrl").
-include("pkt_lldp.hrl").

-export([codec/1]).

codec(Binary) when is_binary(Binary) -> { decode(Binary, []), <<>> };
codec(#lldp{ pdus = Pdus }) -> pad_to(50, encode(Pdus, <<>>)).

decode(<<?END_OF_LLDPDU:7, 0:9, _Tail/bytes>>, Acc) ->
    Acc2 = [#end_of_lldpdu{} | Acc],
    #lldp{ pdus = lists:reverse(Acc2) };
decode(<<?CHASSIS_ID:7, Length:9, SubTypeInt:8, Tail/bytes>>, Acc) ->
    ValueLen = Length - 1,
    <<Value:ValueLen/bytes, Rest/bytes>> = Tail,
    SubType = map(chassis_id, SubTypeInt),
    Pdu = #chassis_id{ subtype = SubType, value = Value },
    decode(Rest, [Pdu | Acc]);
decode(<<?PORT_ID:7, Length:9, SubTypeInt:8, Tail/bytes>>, Acc) ->
    ValueLen = Length - 1,
    <<Value:ValueLen/bytes, Rest/bytes>> = Tail,
    SubType = map(port_id, SubTypeInt),
    Pdu = #port_id{ subtype = SubType, value = Value },
    decode(Rest, [Pdu | Acc]);
decode(<<?TTL:7, Length:9, Tail/bytes>>, Acc) ->
    BitLen = Length * 8,
    <<Value:BitLen, Rest/bytes>> = Tail,
    Pdu = #ttl{ value = Value },
    decode(Rest, [Pdu | Acc]);
decode(<<?PORT_DESC:7, Length:9,
         Value:Length/bytes, Rest/bytes>>, Acc) ->
    Pdu = #port_desc{ value = Value },
    decode(Rest, [Pdu | Acc]);
decode(<<?SYSTEM_NAME:7, Length:9,
         Value:Length/bytes, Rest/bytes>>, Acc) ->
    Pdu = #system_name{ value = Value },
    decode(Rest, [Pdu | Acc]);
decode(<<?SYSTEM_DESC:7, Length:9,
         Value:Length/bytes, Rest/bytes>>, Acc) ->
    Pdu = #system_desc{ value = Value },
    decode(Rest, [Pdu | Acc]);
decode(<<?SYSTEM_CAPABILITY:7, _Length:9, Tail/bytes>>, Acc) ->
    <<System:16, Enabled:16, Rest/bytes>> = Tail,
    Pdu = #system_capability{ system = System,
                              enabled = Enabled },
    decode(Rest, [Pdu | Acc]);
decode(<<?MANAGEMENT_ADDRESS:7, Length:9,
         Value:Length/bytes, Rest/bytes>>, Acc) ->
    Pdu = #management_address{ value = Value },
    decode(Rest, [Pdu | Acc]);
decode(<<?ORGANIZATIONALLY_SPECIFIC:7, Length:9,
         Value:Length/bytes, Rest/bytes>>, Acc) ->
    Pdu = #organizationally_specific{ value = Value },
    decode(Rest, [Pdu | Acc]).

encode([], Binary) -> Binary;
encode([Pdu | Rest], Binary) ->
    PduBin = encode_pdu(Pdu),
    encode(Rest, <<Binary/bytes, PduBin/bytes>>).

encode_pdu(#end_of_lldpdu{}) ->
    <<?END_OF_LLDPDU:7, 0:9>>;
encode_pdu(#chassis_id{ subtype = SubType, value = Value }) ->
    SubTypeInt = map(chassis_id, SubType),
    Length = byte_size(Value),
    <<?CHASSIS_ID:7, (Length + 1):9, SubTypeInt:8, Value:Length/bytes>>;
encode_pdu(#port_id{ subtype = SubType, value = Value }) ->
    SubTypeInt = map(port_id, SubType),
    Length = byte_size(Value),
    <<?PORT_ID:7, (Length + 1):9, SubTypeInt:8, Value:Length/bytes>>;
encode_pdu(#ttl{ value = Value }) ->
    <<?TTL:7, 2:9, Value:16>>;
encode_pdu(#port_desc{ value = Value }) ->
    Length = byte_size(Value),
    <<?PORT_DESC:7, Length:9, Value:Length/bytes>>;
encode_pdu(#system_name{ value = Value }) ->
    Length = byte_size(Value),
    <<?SYSTEM_NAME:7, Length:9, Value:Length/bytes>>;
encode_pdu(#system_desc{ value = Value }) ->
    Length = byte_size(Value),
    <<?SYSTEM_DESC:7, Length:9, Value:Length/bytes>>;
encode_pdu(#system_capability{ system = System,
                               enabled = Enabled }) ->
    Value = <<System:16, Enabled:16>>,
    <<?SYSTEM_CAPABILITY:7, 4:9, Value:4/bytes>>;
encode_pdu(#management_address{ value = Value }) ->
    Length = byte_size(Value),
    <<?MANAGEMENT_ADDRESS:7, Length:9, Value:Length/bytes>>;
encode_pdu(#organizationally_specific{ value = Value }) ->
    Length = byte_size(Value),
    <<?ORGANIZATIONALLY_SPECIFIC:7, Length:9, Value:Length/bytes>>.

% ChassisID SubTypes
map(chassis_id, ?CHASSIS_ID_IFAlias) -> inteface_alias;
map(chassis_id, ?CHASSIS_ID_PORT)    -> port_component;
map(chassis_id, ?CHASSIS_ID_MAC)     -> mac_address;
map(chassis_id, ?CHASSIS_ID_NW)      -> network_address;
map(chassis_id, ?CHASSIS_ID_IFNAME)  -> interface_name;
map(chassis_id, ?CHASSIS_ID_LOCALLY) -> locally_assigned;
map(chassis_id, inteface_alias)   -> ?CHASSIS_ID_IFAlias;
map(chassis_id, port_component)   -> ?CHASSIS_ID_PORT;
map(chassis_id, mac_address)      -> ?CHASSIS_ID_MAC;
map(chassis_id, network_address)  -> ?CHASSIS_ID_NW;
map(chassis_id, interface_name)   -> ?CHASSIS_ID_IFNAME;
map(chassis_id, locally_assigned) -> ?CHASSIS_ID_LOCALLY;

% PortID SubTypes
map(port_id, ?PORT_ID_IFALIAS)       -> interface_alias;
map(port_id, ?PORT_ID_PORT)          -> port_component;
map(port_id, ?PORT_ID_MAC)           -> mac_address;
map(port_id, ?PORT_ID_NW)            -> network_address;
map(port_id, ?PORT_ID_IFNAME)        -> interface_name;
map(port_id, ?PORT_ID_AGENT_CIRC_ID) -> agent_circuit_id;
map(port_id, ?PORT_ID_LOCALLY)       -> locally_assigned;
map(port_id, interface_alias)  -> ?PORT_ID_IFALIAS;
map(port_id, port_component)   -> ?PORT_ID_PORT;
map(port_id, mac_address)      -> ?PORT_ID_MAC;
map(port_id, network_address)  -> ?PORT_ID_NW;
map(port_id, interface_name)   -> ?PORT_ID_IFNAME;
map(port_id, agent_circuit_id) -> ?PORT_ID_AGENT_CIRC_ID;
map(port_id, locally_assigned) -> ?PORT_ID_LOCALLY.

pad_to(ByteLen, Binary) ->
    BinLength = byte_size(Binary),
    case ByteLen > BinLength of
        true ->
            PadLen = (ByteLen - BinLength) * 8,
            <<Binary/bytes, 0:PadLen>>;
        false ->
            Binary
    end.
