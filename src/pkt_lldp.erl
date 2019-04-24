%% Copyright (c) 2009-2015, Michael Santos <michael.santos@gmail.com>
%% All rights reserved.
%%
%% Redistribution and use in source and binary forms, with or without
%% modification, are permitted provided that the following conditions
%% are met:
%%
%% Redistributions of source code must retain the above copyright
%% notice, this list of conditions and the following disclaimer.
%%
%% Redistributions in binary form must reproduce the above copyright
%% notice, this list of conditions and the following disclaimer in the
%% documentation and/or other materials provided with the distribution.
%%
%% Neither the name of the author nor the names of its contributors
%% may be used to endorse or promote products derived from this software
%% without specific prior written permission.
%%
%% THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
%% "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
%% LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
%% FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
%% COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
%% INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
%% BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
%% LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
%% CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
%% LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
%% ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
%% POSSIBILITY OF SUCH DAMAGE.
-module(pkt_lldp).

-include("pkt_ether.hrl").
-include("pkt_lldp.hrl").

-export([codec/1]).

codec(Binary) when is_binary(Binary) -> { decode(Binary, []), <<>> };
codec(#lldp{ pdus = Pdus }) -> pad_to(50, encode(Pdus, <<>>)).

decode(<<?END_OF_LLDPDU:7, 0:9, _Tail/bytes>>, Acc) ->
    Acc2 = [end_of_lldpdu | Acc],
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
    Pdu = #port_desc{ value = decode_string(Value) },
    decode(Rest, [Pdu | Acc]);
decode(<<?SYSTEM_NAME:7, Length:9,
         Value:Length/bytes, Rest/bytes>>, Acc) ->
    Pdu = #system_name{ value = decode_string(Value) },
    decode(Rest, [Pdu | Acc]);
decode(<<?SYSTEM_DESC:7, Length:9,
         Value:Length/bytes, Rest/bytes>>, Acc) ->
    Pdu = #system_desc{ value = decode_string(Value) },
    decode(Rest, [Pdu | Acc]);
decode(<<?SYSTEM_CAPABILITY:7, _Length:9, Tail/bytes>>, Acc) ->
    <<SystemBin:16/bits, EnabledBin:16/bits, Rest/bytes>> = Tail,
    System = binary_to_flags(system_capability, SystemBin),
    Enabled = binary_to_flags(system_capability, EnabledBin),
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
    decode(Rest, [Pdu | Acc]);
decode(<<Type:7, Length:9,
         Value:Length/bytes, Rest/bytes>>, Acc) ->
    Pdu = #unknown_lldp_tlv{ type = Type, value = Value },
    decode(Rest, [Pdu | Acc]).

encode([], Binary) -> Binary;
encode([Pdu | Rest], Binary) ->
    PduBin = encode_pdu(Pdu),
    encode(Rest, <<Binary/bytes, PduBin/bytes>>).

encode_pdu(end_of_lldpdu) ->
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
    Value2 = encode_string(Value),
    Length = byte_size(Value2),
    <<?PORT_DESC:7, Length:9, Value2:Length/bytes>>;
encode_pdu(#system_name{ value = Value }) ->
    Value2 = encode_string(Value),
    Length = byte_size(Value2),
    <<?SYSTEM_NAME:7, Length:9, Value2:Length/bytes>>;
encode_pdu(#system_desc{ value = Value }) ->
    Value2 = encode_string(Value),
    Length = byte_size(Value2),
    <<?SYSTEM_DESC:7, Length:9, Value2:Length/bytes>>;
encode_pdu(#system_capability{ system = System,
                               enabled = Enabled }) ->
    SystemBin = flags_to_binary(system_capability, System, 16),
    EnabledBin = flags_to_binary(system_capability, Enabled, 16),
    Value = <<SystemBin:2/bytes, EnabledBin:2/bytes>>,
    <<?SYSTEM_CAPABILITY:7, 4:9, Value:4/bytes>>;
encode_pdu(#management_address{ value = Value }) ->
    Length = byte_size(Value),
    <<?MANAGEMENT_ADDRESS:7, Length:9, Value:Length/bytes>>;
encode_pdu(#organizationally_specific{ value = Value }) ->
    Length = byte_size(Value),
    <<?ORGANIZATIONALLY_SPECIFIC:7, Length:9, Value:Length/bytes>>.

% ChassisID SubTypes
map(chassis_id, ?CHASSIS_ID_IFAlias) -> interface_alias;
map(chassis_id, ?CHASSIS_ID_PORT)    -> port_component;
map(chassis_id, ?CHASSIS_ID_MAC)     -> mac_address;
map(chassis_id, ?CHASSIS_ID_NW)      -> network_address;
map(chassis_id, ?CHASSIS_ID_IFNAME)  -> interface_name;
map(chassis_id, ?CHASSIS_ID_LOCALLY) -> locally_assigned;
map(chassis_id, interface_alias)  -> ?CHASSIS_ID_IFAlias;
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

% Encode Bitmap flags
flags_to_binary(Type, Flags, BitSize) ->
    flags_to_binary(Type, Flags, BitSize, <<0:BitSize>>).

flags_to_binary(_, [], _, Binary) -> Binary;
flags_to_binary(Type, [Flag | Rest], BitSize, Binary) ->
    <<FlagsInt:BitSize>> = Binary,
    FlagInt = proplists:get_value(Flag, enums(Type)),
    FlagsInt2 = FlagsInt bor FlagInt,
    flags_to_binary(Type, Rest, BitSize, <<FlagsInt2:BitSize>>).

% Decode Bitmap Flags
binary_to_flags(Type, Binary) ->
    BitSize = bit_size(Binary),
    <<FlagsInt:BitSize>> = Binary,
    Keys = proplists:get_keys(enums(Type)),
    binary_to_flags(Type, FlagsInt, Keys, []).

binary_to_flags(_, _, [], Flags) -> lists:reverse(Flags);
binary_to_flags(Type, FlagsInt, [Flag | Rest], Flags) ->
    FlagInt = proplists:get_value(Flag, enums(Type)),
    case 0 /= FlagInt band FlagsInt of
        true ->
            binary_to_flags(Type, FlagsInt, Rest, [Flag | Flags]);
        false ->
            binary_to_flags(Type, FlagsInt, Rest, Flags)
    end.

% system capability enums
enums(system_capability) ->
    [{ other,             ?SYSTEM_CAP_OTHER },
     { repeater,          ?SYSTEM_CAP_REPEATER },
     { bridge,            ?SYSTEM_CAP_BRIDGE },
     { wlan_access_point, ?SYSTEM_CAP_WLANAP },
     { router,            ?SYSTEM_CAP_ROUTER },
     { telephone,         ?SYSTEM_CAP_TELEPHONE },
     { docsis,            ?SYSTEM_CAP_DOCSIS },
     { station_only,      ?SYSTEM_CAP_STATION }].

% padding binary to byte length
pad_to(ByteLen, Binary) ->
    BinLength = byte_size(Binary),
    case ByteLen > BinLength of
        true ->
            PadLen = (ByteLen - BinLength) * 8,
            <<Binary/bytes, 0:PadLen>>;
        false ->
            Binary
    end.

decode_string(Binary) ->
    decode_string(Binary, byte_size(Binary) - 1).

decode_string(Binary, Size) when Size >= 0 ->
    case binary:at(Binary, Size) of
        0 -> decode_string(Binary, Size - 1);
        _ -> binary:part(Binary, 0, Size + 1)
    end;
decode_string(_, _) ->
    <<>>.

encode_string(Binary) -> <<Binary/bytes, 0:8>>.
