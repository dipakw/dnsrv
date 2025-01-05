GOOS=darwin GOARCH=amd64 go build -o dnsrv.mac.bin

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


## DoH Response

```json
{
    "Status": 0,    // 0 : No error (query succeeded).
    "TC": false,    // false : Indicates whether the response was truncated due to size limitations.
    "RD": true,     // RD (Recursion Desired): Indicates whether recursion was requested by the client.
    "RA": true,     // RA (Recursion Available): Indicates whether the DNS server supports recursion.
    "AD": false,    // AD (Authentic Data): Indicates whether the response data is authenticated (DNSSEC).
    "CD": false,    // CD (Checking Disabled): Indicates whether the client disabled DNSSEC validation.

    "Question": [
        {
            "name": "example.com.",
            "type": 1
        }
    ],

    "Answer": [
        {
            "name": "example.com.",
            "type": 1,
            "TTL": 3599,
            "data": "93.184.216.34"
        }
    ],

    "Comment": "Response from 8.8.8.8"
}
```