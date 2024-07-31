package dns

import "encoding/binary"

func parse(packet []byte) (string, uint16, int) {
	var qname string
	i := 12

	for {
		length := int(packet[i])

		if length == 0 {
			break
		}

		if i != 12 {
			qname += "."
		}

		qname += string(packet[i+1 : i+1+length])
		i += length + 1
	}

	qtype := binary.BigEndian.Uint16(packet[i+1 : i+3])
	// 16 bytes header + qname + 2 bytes type + 2 bytes class
	return qname, qtype, i + 5
}
