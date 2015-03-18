%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% End of LLDPDU
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-define(END_OF_LLDPDU, 0).

-record(end_of_lldpdu, {}).
-type end_of_lldpdu() :: #end_of_lldpdu{}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% Chassis Id
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-define(CHASSIS_ID, 1).

-define(CHASSIS_ID_CHASSIS, 1).
-define(CHASSIS_ID_IFAlias, 2).
-define(CHASSIS_ID_PORT,    3).
-define(CHASSIS_ID_MAC,     4).
-define(CHASSIS_ID_NW,      5).
-define(CHASSIS_ID_IFNAME,  6).
-define(CHASSIS_ID_LOCALLY, 7).

-type chassis_id_subtype() :: chassis_component
                            | interface_alias
                            | port_component
                            | mac_address
                            | network_address
                            | interface_name
                            | locally_assigned.

-record(chassis_id, { subtype = locally_assigned :: chassis_id_subtype(),
                      value   = <<>>             :: binary() }).
-type chassis_id() :: #chassis_id{}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% Port Id
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-define(PORT_ID, 2).

-define(PORT_ID_IFALIAS,       1).
-define(PORT_ID_PORT,          2).
-define(PORT_ID_MAC,           3).
-define(PORT_ID_NW,            4).
-define(PORT_ID_IFNAME,        5).
-define(PORT_ID_AGENT_CIRC_ID, 6).
-define(PORT_ID_LOCALLY,       7).

-type port_id_subtype() :: interface_alias
                         | port_component
                         | mac_address
                         | network_address
                         | interface_name
                         | agent_circuit_id
                         | locally_assigned.

-record(port_id, { subtype = locally_assigned :: port_id_subtype(),
                   value   = <<>>             :: binary() }).
-type port_id() :: #port_id{}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% TTL
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-define(TTL, 3).

-record(ttl, { value = 0 :: non_neg_integer() }).
-type ttl() :: #ttl{}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% Port Description
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-define(PORT_DESC, 4).

-record(port_desc, { value = <<>> :: binary() }).
-type port_desc() :: #port_desc{}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% System Name
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-define(SYSTEM_NAME, 5).

-record(system_name, { value = <<>> :: binary() }).
-type system_name() :: #system_name{}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% System Description
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-define(SYSTEM_DESC, 6).

-record(system_desc, { value = <<>> :: binary() }).
-type system_desc() :: #system_desc{}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% System Capability
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-define(SYSTEM_CAPABILITY, 7).

-type capability_flag() :: other
                         | repeater
                         | bridge
                         | wlan_access_point
                         | router
                         | telephone
                         | docsis
                         | station_only.

-define(SYSTEM_CAP_OTHER,     1 bsl 0).
-define(SYSTEM_CAP_REPEATER,  1 bsl 1).
-define(SYSTEM_CAP_BRIDGE,    1 bsl 2).
-define(SYSTEM_CAP_WLANAP,    1 bsl 3).
-define(SYSTEM_CAP_ROUTER,    1 bsl 4).
-define(SYSTEM_CAP_TELEPHONE, 1 bsl 5).
-define(SYSTEM_CAP_DOCSIS,    1 bsl 6).
-define(SYSTEM_CAP_STATION,   1 bsl 7).

-record(system_capability, { system  = [] :: [capability_flag()],
                             enabled = [] :: [capability_flag()] }).
-type system_capability() :: #system_capability{}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% Management Address
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-define(MANAGEMENT_ADDRESS, 8).

-record(management_address, { value = <<>> :: binary() }).
-type management_address() :: #management_address{}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% Organizationally Specific
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-define(ORGANIZATIONALLY_SPECIFIC, 127).

-record(organizationally_specific, { value = <<>> :: binary() }).
-type organizationally_specific() :: #organizationally_specific{}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% LLDP Frame Format
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-type pdu() :: chassis_id()
             | port_id()
             | ttl()
             | port_desc()
             | system_name()
             | system_desc()
             | system_capability()
             | management_address()
             | organizationally_specific().

-record(lldp, { pdus = [] :: [pdu()] }).
-type lldp() :: #lldp{}.
