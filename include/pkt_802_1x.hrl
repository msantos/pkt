-define(EAP_PACKET, 0).           % Contains encapsulate EAP frame
-define(EAPOL_START, 1).          % A supplicant issued frame  
-define(EAPOL_LOGOFF, 2).         % Logoff to switch port to unauthorized state
-define(EAPOL_KEY, 3).            % Exchange cryptographic keying information
-define(EAPOL_ENCAPSULATED_ASF_ALERT, 4). % Alerting unauthorized state 

-record('802.1x', {
	  ver = 2 :: pkt:uint8_t(),
	  type = 0 :: pkt:uint8_t(),
	  len = 0 :: pkt:uint16_t()
  }).
