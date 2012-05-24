
An Erlang network protocol library.

Originally part of epcap:
<http://github.com/msantos/epcap>


## EXPORTS

    pkt:decapsulate(Data) -> Packet
    
        Types   Data = binary()
                Packet = [ Headers, Payload ]
                Headers = Header
                Header = {ether, binary()} | {arp, binary()} | {null, binary()} |
                    {linux_cooked, binary()} | {ipv4, binary()} |
                    {ipv6, binary()} | {tcp, binary()} | {udp, binary()} |
                    {sctp, binary()} | {icmp, binary()} | {unsupported, binary()}
                Payload = binary()
    
        Attempts to decapsulate the packet into a list of tuples.


The following functions create the protocol headers, converting between
records and binaries. See include/pkt.hrl for definition of the record
types.

    ether(Packet) -> {#ether{}, Payload} | binary()
    null(Packet) -> {#null{}, Payload} | binary()
    linux_cooked(Packet) -> {#linux_cooked{}, Payload} | binary()
    arp(Packet) -> {#arp{}, Payload} | binary()
    ipv4(Packet) -> {#ipv4{}, Payload} | binary()
    ipv6(Packet) -> {#ipv6{}, Payload} | binary()
    tcp(Packet) -> {#tcp{}, Payload} | binary()
    sctp(Packet) -> {#sctp{}, Payload} | binary()
    udp(Packet) -> {#udp{}, Payload} | binary()
    icmp(Packet) -> {#icmp{}, Payload} | binary()
    icmp6(Packet) -> {#icmp6{}, Payload} | binary()
    
        Types   Packet = Header | binary()
                Header = #ether{} | #null{} | #linux_cooked{} | #arp{} |
                    #ipv4{} | #ipv6{} | #tcp{} | #sctp{} | #udp{} |
                    #icmp{} | #icmp6{}

    
    makesum(Packet) -> integer()
    
        Types   Packet = IPv4_header | [IPv4_header, Header, Payload]
                IPv4_header = #ipv4{}
                Header = #tcp{} | #udp{}
                Payload = binary()
    
        Calculate the checksum of the packet. 


## TODO

* DLTs
    * DLT_SLIP
    * DLT_PPP
    * DLT_RAW
    * DLT\_PPP\_SERIAL
    * DLT\_PPP\_ETHER
    * DLT\_IEEE802\_11
    * DLT_LOOP


## CONTRIBUTORS

* Olivier Girondel:
    * preliminary IPv6 support

* Harald Welte:
    * support reading packets from pcap file
    * SCTP support
    * datalink types

* Gregory Haskins:
    * application file fix

* Alexey Larin
    * GRE support
