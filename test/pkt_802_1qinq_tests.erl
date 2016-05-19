-module(pkt_802_1qinq_tests).

-include_lib("pkt/include/pkt.hrl").
-include_lib("eunit/include/eunit.hrl").

codec_test_() ->
    [
        frame_decode(),
        decode(),
        encode()
    ].

% https://github.com/the-tcpdump-group/tcpdump/blob/master/tests/QinQpacket.pcap
frame() ->
    <<255,255,255,255,255,255,0,8,93,35,12,63,136,168,0,200,8,
      6,0,1,8,0,6,4,0,1,0,8,93,35,12,63,172,17,0,20,0,0,0,0,0,
      0,172,17,0,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>.

header() ->
    <<0,200,8,6>>.

frame_decode() ->
    Frame = pkt:decapsulate(frame()),
    Terms = [#ether{dhost = <<255,255,255,255,255,255>>,
                    shost = <<0,8,93,35,12,63>>,
                    type = 34984,crc = 0},
                    #'802.1q'{prio = 0,cfi = 0,vid = 200,type = 2054},
                    #arp{hrd = 1,pro = 2048,hln = 6,pln = 4,op = 1,
                         sha = <<0,8,93,35,12,63>>,
                         sip = {172,17,0,20},
                         tha = <<0,0,0,0,0,0>>,
                         tip = {172,17,0,2}},
              <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>],
    ?_assertEqual(Terms, Frame).

decode() ->
    {Header, Payload} = pkt:'802.1q'(header()),
    Result = #'802.1q'{
        prio = 0,
        cfi = 0,
        vid = 200,
        type = 16#0806
    },
    ?_assertEqual({Result, <<>>}, {Header, Payload}).

encode() ->
    Packet = header(),
    {Header, Payload} = pkt:'802.1q'(Packet),
    ?_assertEqual(Packet, <<(pkt:'802.1q'(Header))/binary, Payload/binary>>).
