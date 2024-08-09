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

## Unsupported records

1. CAA
2. CERT
3. DNSKEY
4. DS
5. HTTPS
6. LOC
7. NAPTR
8. SMIMEA
9. SSHFP
10. SVCB
11. TLSA
12. URI

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

  NS:
    _@:
      default:
        ttl: 0
        values:
          - "ns1.example.com"
          - "ns2.example.com"

  MX:
    _@:
      default:
        ttl: 0
        values:
          - "10 mail1.example.com"
          - "10 mail2.example.com"

  A:
    _@:
      default:
        ttl: 0
        values:
          - 193.168.0.2

      regions:
        NA_US:
          ttl: 0
          values:
            - 193.168.0.3

    www:
      default:
        ttl: 0
        values:
          - 133.168.0.2

    dash:
      default:
        ttl: 0
        values:
          - 167.23.4.24

  AAAA:
    _@:
      default:
        ttl: 0
        values:
          - 2001:0db8:85a3:0000:0000:8a2e:0370:7334
```