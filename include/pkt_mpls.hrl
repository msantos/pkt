-define(MPLS_LABEL_IPV4NULL, 0).
-define(MPLS_LABEL_RTALERT, 1).
-define(MPLS_LABEL_IPV6NULL, 2).
-define(MPLS_LABEL_IMPLNULL, 3).
-define(MPLS_LABEL_ENTROPY, 7).
-define(MPLS_LABEL_GAL, 13).
-define(MPLS_LABEL_OAMALERT, 14).
-define(MPLS_LABEL_EXTENSION, 15).
-define(MPLS_LABEL_FIRST_UNRESERVED, 16).

%% Reference: RFC 5462, RFC 3032
%%
%%   0                   1                   2                   3
%%   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
%%  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%%  |                Label                  | TC  |S|       TTL     |
%%  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%%
%% 	Label:  Label Value, 20 bits
%% 	TC:     Traffic Class field, 3 bits
%% 	S:      Bottom of Stack, 1 bit
%% 	TTL:    Time to Live, 8 bits
%%

-record(shim, {label = 0 :: 1..16#fffff,
               tc = 0 :: 1..7,
               s = true :: boolean(),
               ttl = 0 :: pkt:uint8_t()}).
-type shim() :: #shim{}.

-record(mpls, {labels = [] :: [shim()]}).
-type mpls() :: #mpls{}.
