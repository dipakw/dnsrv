package record

import (
	"encoding/base64"
	"encoding/binary"
)

func (r *CERT) Encode() []*Answer {
	answers := []*Answer{}

	for _, rec := range r.Records {
		certificate, _ := base64.StdEncoding.DecodeString(rec.Cert)

		answer := &Answer{
			Name:  0xC00C,
			Type:  37,
			Class: 1,
			TTL:   rec.TTL,
			Data:  make([]byte, 5+len(certificate)),
		}

		binary.BigEndian.PutUint16(answer.Data[0:2], rec.Type)
		binary.BigEndian.PutUint16(answer.Data[2:4], rec.KeyTag)
		answer.Data[4] = rec.Algo
		copy(answer.Data[5:], certificate)

		answer.Len = uint16(len(answer.Data))
		answers = append(answers, answer)
	}

	return answers
}
