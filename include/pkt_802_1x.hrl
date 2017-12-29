-define(EAP_PACKET, 0).           % EAPOL-PACKET 
-define(EAPOL_START, 1).          % EAPOL-START  
-define(EAPOL_LOGOFF, 2).         % EAPOL-LOGOFF
-define(EAPOL_KEY, 3).            % EAPOL-KEY
-define(EAPOL_ENCAPSULATED_ASF_ALERT, 4). % EAPOL-ENCAPSULATED-ASF-ALERT

-record('802.1x', {
	  ver = 2 :: pkt:uint8_t(),
	  type = 0 :: pkt:uint8_t(),
	  len = 0 :: pkt:uint16_t()
  }).
