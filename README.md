GOOS=darwin GOARCH=amd64 go build -o dnsrv.mac.bin

Example zone:

```yaml
zone: example.com.

records:
  SOA:
    name: "ns1.example.com."
    admin: "admin.example.com."
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
          - "ns1.example.com."
          - "ns2.example.com."

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
          
        NS_OV:
          ttl: 0
          values:
            - 193.168.0.4
        
        EU_DE:
          ttl: 0
          values:
            - 193.168.0.5

  AAAA:
    _@:
      default:
        ttl: 0
        values:
          - 2001:0db8:85a3:0000:0000:8a2e:0370:7334
```