package dns

import (
	"fmt"
	"net"
	"strings"
)

func resolve(ip net.IP, host string, rectype uint16) *Entry {

	name := "_@"
	zone := zones[host]

	if zone == nil {
		parts := strings.Split(host, ".")
		lenth := len(parts)

		for i := 1; i <= lenth; i++ {
			if i == lenth {
				continue
			}

			name = strings.Join(parts[0:i], ".")
			zone = zones[strings.Join(parts[i:lenth], ".")]

			if zone != nil {
				break
			}
		}
	}

	var record *Record = nil
	var soa *SOA = nil

	if zone != nil {

		recsmap := map[uint16]map[string]*Record{
			1:  zone.Records.A,
			28: zone.Records.AAAA,
			16: zone.Records.TXT,
			5:  zone.Records.CNAME,
			15: zone.Records.MX,
			2:  zone.Records.NS,
			12: zone.Records.PTR,
			33: zone.Records.SRV,
		}

		if r, exists := recsmap[rectype]; exists {
			record = r[name]
		}

		if rectype == 6 {
			soa = zone.Records.SOA
		}

	}

	if record != nil {
		record.Default.Type = rectype
		return record.Default
	}

	if soa != nil {
		return &Entry{
			TTL:  0,
			Type: rectype,
			Values: []string{
				fmt.Sprintf(
					"%s %s %d %d %d %d %d",
					soa.Name,
					soa.Admin,
					soa.Serial,
					soa.Refresh,
					soa.Retry,
					soa.Expire,
					soa.Minimum,
				),
			},
		}
	}

	return nil
}
