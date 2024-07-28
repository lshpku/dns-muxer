# DNSMuxer

DNSMuxer forwards DNS queries to a plain DNS server or a DoT server based on their respective regions.

```text
 DNS Queries
      |
      v         CN?
   DNSMuxer  <------->  GeoIP/GeoData
      /\
 CN /    \ !CN
   |      |
   v      v
 Plain   DoT
```
