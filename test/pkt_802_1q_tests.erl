-module(pkt_802_1q_tests).

-include_lib("pkt/include/pkt.hrl").
-include_lib("eunit/include/eunit.hrl").

codec_test_() ->
    [
        frame_decode(),
        decode(),
        encode()
    ].

% http://packetlife.net/captures/QinQ.pcap.cap
frame() ->
    <<255,255,255,255,255,255,202,3,13,180,0,28,129,0,0,100,
      129,0,0,200,8,6,0,1,8,0,6,4,0,1,202,3,13,180,0,28,192,
      168,2,200,0,0,0,0,0,0,192,168,2,254,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0>>.

header() ->
    <<0,100,129,0>>.

frame_decode() ->
    Frame = pkt:decapsulate(frame()),
    Terms =[#ether{dhost = <<255,255,255,255,255,255>>,
                   shost = <<202,3,13,180,0,28>>,
                   type = 33024,crc = 0},
            #'802.1q'{prio = 0,cfi = 0,vid = 100,type = 33024},
            #'802.1q'{prio = 0,cfi = 0,vid = 200,type = 2054},
            #arp{hrd = 1,pro = 2048,hln = 6,pln = 4,op = 1,
                 sha = <<202,3,13,180,0,28>>,
                 sip = {192,168,2,200},
                 tha = <<0,0,0,0,0,0>>,
                 tip = {192,168,2,254}},
            <<0,0,0,0,0,0,0,0,0,0,0,0,0,0>>],
    ?_assertEqual(Terms, Frame).

decode() ->
    {Header, Payload} = pkt:'802.1q'(header()),
    Result = #'802.1q'{
        prio = 0,
        cfi = 0,
        vid = 100,
        type = 16#8100
    },
    ?_assertEqual({Result, <<>>}, {Header, Payload}).

encode() ->
    Packet = header(),
    {Header, Payload} = pkt:'802.1q'(Packet),
    ?_assertEqual(Packet, <<(pkt:'802.1q'(Header))/binary, Payload/binary>>).
