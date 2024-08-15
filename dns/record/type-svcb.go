package record

import (
	"bytes"
	"encoding/binary"
	"net"
)

func (r *SVCB) Encode() []*Answer {
	answers := []*Answer{}

	for _, rec := range r.Records {
		target := []byte("")

		if rec.Target != "" && rec.Target != "." {
			target = encodeName(rec.Target)
		}

		answer := &Answer{
			Name:  0xC00C,
			Type:  64,
			Class: 1,
			TTL:   rec.TTL,
		}

		var params []byte

		if len(rec.Mandatory) > 0 {
			mdtry := []byte{}

			for _, part := range rec.Mandatory {
				id, ex := getKeyId(part)

				if !ex {
					continue
				}

				mdtry = append(mdtry, id...)
			}

			params = append(params, 0x00, 0x00)
			params = append(params, intTo2Bytes(len(mdtry))...)
			params = append(params, mdtry...)
		}

		if len(rec.ALPN) > 0 {
			alpns := []byte{}

			for _, part := range rec.ALPN {
				bpart := []byte(part)
				alpns = append(alpns, uint8(len(bpart)))
				alpns = append(alpns, bpart...)
			}

			params = append(params, 0x00, 0x01)
			params = append(params, intTo2Bytes(len(alpns))...)
			params = append(params, alpns...)
		}

		if rec.NoDefaultALPN {
			params = append(params, 0x00, 0x02, 0x00, 0x00)
		}

		if rec.Port > 0 {
			pdata := make([]byte, 2)
			binary.BigEndian.PutUint16(pdata, rec.Port)

			params = append(params, 0x00, 0x03)
			params = append(params, intTo2Bytes(len(pdata))...)
			params = append(params, pdata...)
		}

		if len(rec.IPv4Hint) > 0 {
			ipb := []byte{}

			for _, ip := range rec.IPv4Hint {
				ipb = append(ipb, net.ParseIP(ip).To4()...)
			}

			params = append(params, 0x00, 0x04)
			params = append(params, intTo2Bytes(len(ipb))...)
			params = append(params, ipb...)
		}

		if len(rec.IPv6Hint) > 0 {
			ipb := []byte{}

			for _, ip := range rec.IPv6Hint {
				ipb = append(ipb, net.ParseIP(ip).To16()...)
			}

			params = append(params, 0x00, 0x06)
			params = append(params, intTo2Bytes(len(ipb))...)
			params = append(params, ipb...)
		}

		if rec.DOHPath != "" {
			bdohp := []byte(rec.DOHPath)
			params = append(params, 0x00, 0x07)
			params = append(params, intTo2Bytes(len(bdohp))...)
			params = append(params, bdohp...)
		}

		for key, value := range rec.Other {
			id, exists := getKeyId(key)

			if !exists {
				continue
			}

			valby := []byte(value)
			params = append(params, id...)
			params = append(params, intTo2Bytes(len(valby))...)
			params = append(params, valby...)
		}

		var buffer bytes.Buffer

		binary.Write(&buffer, binary.BigEndian, rec.Priority)

		if len(target) > 0 {
			buffer.Write(target)
		}

		if len(params) > 0 {
			buffer.Write([]byte{0x00})
			buffer.Write(params)
		}

		answer.Data = buffer.Bytes()
		answer.Len = uint16(len(answer.Data))

		answers = append(answers, answer)
	}

	return answers
}
