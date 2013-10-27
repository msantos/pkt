
An Erlang network protocol library.

Originally part of epcap:
<http://github.com/msantos/epcap>


## EXPORTS

    pkt:decapsulate(Data) -> Packet
    pkt:decapsulate(Proto, Data) -> Packet
    
        Types   Data = binary()
                Proto = atom() | integer()
                Packet = [ Header | Payload ]
                Header = #ether{} | #arp{} | #null{} | #linux_cooked{} |
                    #ipv4{} | #ipv6{} | #tcp{} | #udp{} | #sctp{} | #icmp{} |
                    #icmp6{} | #gre{}
                Payload = binary()

        Convert network protocols from binary data to a list of Erlang
        records followed by the payload.

        decapsulate/1,2 works on valid packets. If the packet is malformed
        or unsupported, decapsulate/1 will crash.

        decapsulate/1 parses the data as an ethernet frame.

        decapsulate/2 allows specifying the protocol for decoding the
        packet. If the protocol is specified as an integer, the integer
        is treated as a datalink type.

    pkt:decode(Data) -> {ok, Packet} | {error, SoFar, {FailedProto, binary()}}
    pkt:decode(Proto, Data) -> {ok, Packet} | {error, SoFar, {FailedProto, binary()}}

        Types   Data = binary()
                Proto = FailedProto = atom()
                Packet = {Headers, Payload}
                Headers = [Header]
                Header = #ether{} | #arp{} | #null{} | #linux_cooked{} |
                    #ipv4{} | #ipv6{} | #tcp{} | #udp{} | #sctp{} | #icmp{} |
                    #icmp6{} | #gre{}
                SoFar = Headers | []
                Payload = binary()

        Similar to decapsulate/1 but, on error, returns any part of the
        packet that has been successfully converted to Erlang term format.

The following functions create the protocol headers, converting between
records and binaries. See include/pkt.hrl for definition of the record
types.

    ether(Packet) -> {#ether{}, Payload} | binary()
    null(Packet) -> {#null{}, Payload} | binary()
    linux_cooked(Packet) -> {#linux_cooked{}, Payload} | binary()
    gre(Packet) -> {#gre{}, Payload} | binary()
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
                    #icmp{} | #icmp6{} | #gre{}

    
    makesum(Packet) -> integer()
    
        Types   Packet = IPv4_header | [IPv4_header, Header, Payload]
                IPv4_header = #ipv4{}
                Header = #tcp{} | #udp{}
                Payload = binary()
    
        Calculate the one's complement checksum of the packet.

        When computing the checksum, the header sum field must be set
        to 0:

            Sum = pkt:makesum([IPv4, TCP#tcp{sum = 0}, Payload]).

        For verifcation, the checksum can be compared to the value in
        the header or:

            0 = pkt:makesum([IPv4, TCP, Payload]).

## EXAMPLES

* decode an ethernet frame, displaying the source and destination of
  valid packets

```erlang
Frame = <<224,105,149,59,163,24,0,22,182,181,62,198,8,0,69,0,0,54,2,108,64,
          0,53,6,172,243,173,192,82,195,192,168,213,54,0,80,143,166,75,154,
          212,181,116,33,53,92,128,24,0,126,60,199,0,0,1,1,8,10,92,104,96,
          16,22,69,237,136,137,0>>,

try pkt:decapsulate(Frame) of
    [#ether{}, #ipv4{saddr = Saddr, daddr = Daddr},
        #tcp{sport = Sport, dport = Dport}, _Payload] ->
        {{Saddr, Sport}, {Daddr, Dport}}
catch
    error:_ ->
        ok; % ignore invalid packets
end
```

* verify the TCP checksum of an ethernet frame

```erlang
{ok, [#ether{}, IPv4, #tcp{sum = Sum} = TCP, Payload]} = pkt:decode(ether, Frame),

% Re-calculate the checksum and match against the checksum in the header
Sum = pkt:makesum([IPv4, TCP#tcp{sum = 0}, Payload]),

% Or just verify the checksum
0 = pkt:makesum([IPv4, TCP, Payload]).
```

## TODO

* support RFC 2675 (IPv6 Jumbograms)

* IPv6 AH and ESP
    * handle alignment differences between IPv4 and IPv6 (IPv4 uses 32
      bits, IPv6 uses 64 bits)

* ICMPv6
    * fix handling of neighbour discovery
    * simplify ICMPv6 header record and add a record for ICMPv6 type or
      add functions for ICMPv6 variable length payloads

* merge in DLT\_IEEE802\_11 support from wierl

* merge in ICMPv6 code from gen_icmp

* DLTs
    * DLT_SLIP
    * DLT_PPP
    * DLT_RAW
    * DLT\_PPP\_SERIAL
    * DLT\_PPP\_ETHER
    * DLT_LOOP
