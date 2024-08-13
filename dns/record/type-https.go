package record

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
)

func (r *HTTPS) Encode() []*Answer {
	answers := []*Answer{}

	for _, rec := range r.Records {
		target := []byte("")

		if rec.Target != "." {
			target = encodeName(rec.Target)
		}

		answer := &Answer{
			Name:  0xC00C,
			Type:  65,
			Class: 1,
			TTL:   rec.TTL,
		}

		var params []byte

		if rec.ALPN != "" {
			parts := strings.Split(rec.ALPN, ",")
			alpns := []byte{}

			for _, part := range parts {
				bpart := []byte(part)
				alpns = append(alpns, uint8(len(bpart)))
				alpns = append(alpns, bpart...)
			}

			params = append(params, 0x01, 0x00)
			params = append(params, uint8(len(alpns)))
			params = append(params, alpns...)
		}

		if rec.IPv6Hint != "" {
			ips := strings.Split(rec.IPv6Hint, ",")
			ipb := []byte{}

			if len(params) > 0 {
				params = append(params, 0x00)
			}

			for _, ip := range ips {
				ipb = append(ipb, net.ParseIP(ip).To16()...)
			}

			params = append(params, 0x06, 0x00)
			params = append(params, uint8(len(ipb)))
			params = append(params, ipb...)
		}

		if rec.IPv4Hint != "" {
			ips := strings.Split(rec.IPv4Hint, ",")
			ipb := []byte{}

			if len(params) > 0 {
				params = append(params, 0x00)
			}

			for _, ip := range ips {
				ipb = append(ipb, net.ParseIP(ip).To4()...)
			}

			params = append(params, 0x04, 0x00)
			params = append(params, uint8(len(ipb)))
			params = append(params, ipb...)
		}

		var buffer bytes.Buffer

		binary.Write(&buffer, binary.BigEndian, rec.Priority)

		if len(target) > 0 {
			buffer.Write(target)
		}

		if len(params) > 0 {
			buffer.Write([]byte{0x00, 0x00})
			buffer.Write(params)
		}

		answer.Data = buffer.Bytes()
		answer.Len = uint16(len(answer.Data))

		answers = append(answers, answer)
	}

	return answers
}
