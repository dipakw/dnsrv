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

		if rectype == 6 {
			return zone.Records.SOA
		}

		if rectype == 1 {
			if entry, ok := zone.Records.A[name]; ok {
				return entry.Default
			}
		}

		if rectype == 28 {
			if entry, ok := zone.Records.AAAA[name]; ok {
				return entry.Default
			}
		}

		if rectype == 16 {
			if entry, ok := zone.Records.TXT[name]; ok {
				return entry.Default
			}
		}

		if rectype == 5 {
			if entry, ok := zone.Records.CNAME[name]; ok {
				return entry.Default
			}
		}

		if rectype == 15 {
			if entry, ok := zone.Records.MX[name]; ok {
				return entry.Default
			}
		}

		if rectype == 2 {
			if entry, ok := zone.Records.NS[name]; ok {
				return entry.Default
			}
		}

		if rectype == 12 {
			if entry, ok := zone.Records.PTR[name]; ok {
				return entry.Default
			}
		}

		if rectype == 33 {
			if entry, ok := zone.Records.SRV[name]; ok {
				return entry.Default
			}
		}

	}

	return nil
}
