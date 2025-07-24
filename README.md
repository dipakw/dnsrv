## dnsrv
This is a lightweight DNS server written in Go that uses YAML files and supports all 21 DNS record types supported by Cloudflare.

## Build
```bash
go build
```

## Run
Ensure that the `zones.d` directory exists in the same location as the binary.

Create the necessary zone files in the `zones.d` directory. Refer to the `sample-zone.yml` file to understand the required format and structure for your zone files.


## Supported records

1. SOA
2. A
3. AAAA
4. TXT
5. CNAME
6. MX
7. NS
8. PTR
9. SRV
10. CAA
11. CERT
12. DNSKEY
13. DS
14. HTTPS
15. LOC
16. NAPTR
17. SMIMEA
18. SSHFP
19. SVCB
20. TLSA
21. URI
