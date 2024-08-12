package dns

import (
	"net"
	"strings"
)

func resolve(ip net.IP, host string, rectype uint16) Entry {

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

	if zone != nil {

		if rectype == 1 {
			if entry, ok := zone.Records.A[name]; ok {
				return entry.Default
			}
		}

		/*recsmap := map[uint16]map[string]*Record{
			1:  zone.Records.A,
			28: zone.Records.AAAA,
			16: zone.Records.TXT,
			5:  zone.Records.CNAME,
			15: zone.Records.MX,
			2:  zone.Records.NS,
			12: zone.Records.PTR,
			33: zone.Records.SRV,
		} */

	}

	return nil
}
