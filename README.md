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

## Unsupported records

1. DNSKEY
2. DS
3. HTTPS
4. LOC
5. NAPTR
6. SMIMEA
7. SSHFP
8. SVCB
9. TLSA
10. URI

Example zone:

```yaml
zone: example.com

records:
  SOA:
    name: "ns1.example.com"
    admin: "admin.example.com"
    serial: 2024080901
    refresh: 3600
    retry: 1800
    expire: 1209600
    minimum: 86400
    ttl: 0

  A:
    _@:
      default:
        records:
          - ttl: 0
            ipv4: 193.168.0.2

          - ttl: 0
            ipv4: 193.168.0.3

  AAAA:
    _@:
      default:
        records:
          - ttl: 0
            ipv6: 2001:0db8:85a3:0000:0000:8a2e:0370:7334

  TXT:
    _@:
      default:
        records:
          - ttl: 0
            value: "I am here!"

          - ttl: 0
            value: APIKEYGOESHERE

  CNAME:
    _@:
      default:
        ttl: 0
        target: www.woo.com

  MX:
    _@:
      default:
        records:
          - ttl: 1
            priority: 5
            server: mail1.woo.com

          - ttl: 2
            priority: 10
            server: mail2.woo.com

  NS:
    _@:
      default:
        records:
          - ttl: 1
            server: ns1.woo.com

          - ttl: 2
            server: ns2.woo.com

  PTR:
    _@:
      default:
        records:
          - ttl: 1
            domain: ptr1.woo.com

          - ttl: 2
            domain: ptr2.woo.com

  SRV:
    _@:
      default:
        records:
          - ttl: 1
            target: sip1.woo.com
            priority: 100
            weight: 101
            port: 7767
```