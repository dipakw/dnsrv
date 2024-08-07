package dns

import (
	"net"
)

func resolve(ip net.IP, host string, record uint16) []string {

	switch host {

	case "www.example.com":
		switch record {
		case 1:
			return []string{"A 122.34.56.6"}
		case 28:
			return []string{"AAAA 2001:0db8:85a3:0000:0000:8a2e:0370:7334"}
		case 16:
			return []string{"TXT v=spf1 include:_spf.example.com ~all"}
		case 5:
			return []string{"CNAME example.com"}
		case 15:
			return []string{
				"MX 10 mail1.example.com",
				"MX 20 mail2.example.com",
				"MX 50 mail3.example.com",
			}
		case 2:
			return []string{"NS ns1.example.com"}
		case 12:
			return []string{"PTR ptr.example.com"}
		case 33:
			return []string{"SRV 0 5 5060 sip.example.com"}
		case 6:
			return []string{"SOA ns1.example.com hostmaster.example.com 2024040801 7200 3600 1209600 3600"}
		}
	}

	return []string{}
}
