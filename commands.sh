
########################################
#            Launch DNSMuxer
########################################
dnsmuxer_args="
-forward 172.20.10.1:53
-listen 127.0.0.1:8053
-log-level debug
-forward-proxy 127.0.0.1:1081
-query-cn 127.0.0.1:8063
"

bin/dnsmuxer-darwin-amd64 $dnsmuxer_args


########################################
#           Make DNS Queries
########################################

dig @127.0.0.1 -p 8053 baidu.com

dig @127.0.0.1 -p 8053 google.com

dig @127.0.0.1 -p 8053 +vc google.com

dig @127.0.0.1 -p 8053 google.com AAAA
