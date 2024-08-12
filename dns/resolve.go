package dns

import (
	"net"
	"strings"
)

func resolve(ip net.IP, host string, rectype uint16) Entry {

	name := "_@"
	zone := zones[host]
	regn := Geo(ip)

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
		switch rectype {
		case 6:
			return zone.Records.SOA
		case 1:
			if record := zone.Records.A[name]; record != nil {
				return record.Resolve(regn)
			}
		case 28:
			if record := zone.Records.AAAA[name]; record != nil {
				return record.Resolve(regn)
			}
		case 16:
			if record := zone.Records.TXT[name]; record != nil {
				return record.Resolve(regn)
			}
		case 5:
			if record := zone.Records.CNAME[name]; record != nil {
				return record.Resolve(regn)
			}
		case 15:
			if record := zone.Records.MX[name]; record != nil {
				return record.Resolve(regn)
			}
		case 2:
			if record := zone.Records.NS[name]; record != nil {
				return record.Resolve(regn)
			}
		case 12:
			if record := zone.Records.PTR[name]; record != nil {
				return record.Resolve(regn)
			}
		case 33:
			if record := zone.Records.SRV[name]; record != nil {
				return record.Resolve(regn)
			}
		case 257:
			if record := zone.Records.CAA[name]; record != nil {
				return record.Resolve(regn)
			}
		}
	}

	return nil
}

func (r *Record[T]) Resolve(region string) *T {
	if regional, ok := r.Regions[region]; ok {
		return regional
	}

	return r.Default
}
