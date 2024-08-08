package dns

import (
	"net"
)

func resolve(ip net.IP, host string, rectype uint16) *Record {

	record := &Record{
		TTL:     0,
		Answers: []string{},
	}

	if host == "www.example.com" {
		switch rectype {

		case 1:
			record.Answers = []string{"A 122.34.56.6"}
		case 28:
			record.Answers = []string{"AAAA 2001:0db8:85a3:0000:0000:8a2e:0370:7334"}
		case 16:
			record.Answers = []string{"TXT v=spf1 include:_spf.example.com ~all"}
		case 5:
			record.Answers = []string{"CNAME example.com"}
		case 15:
			record.Answers = []string{
				"MX 10 mail1.example.com",
				"MX 20 mail2.example.com",
				"MX 50 mail3.example.com",
			}
		case 2:
			record.Answers = []string{
				"NS ns1.example.com",
				"NS ns2.example.com",
			}
		case 12:
			record.Answers = []string{"PTR ptr.example.com"}
		case 33:
			record.Answers = []string{"SRV 0 5 5060 sip.example.com"}
		case 6:
			record.Answers = []string{"SOA ns1.example.com ns2.example.com 2024040801 7200 3600 1209600 3600"}
		}
	}

	return record
}
