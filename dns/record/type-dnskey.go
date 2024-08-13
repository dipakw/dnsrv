package record

import (
	"encoding/base64"
	"encoding/binary"
)

func (r *DNSKEY) Encode() []*Answer {
	answers := []*Answer{}

	for _, rec := range r.Records {
		publicKey, _ := base64.StdEncoding.DecodeString(rec.PublicKey)

		answer := &Answer{
			Name:  0xC00C,
			Type:  48,
			Class: 1,
			TTL:   rec.TTL,
			Data:  make([]byte, 4+len(publicKey)),
		}

		binary.BigEndian.PutUint16(answer.Data[0:2], rec.Flags)
		answer.Data[2] = rec.Proto
		answer.Data[3] = rec.Algo
		copy(answer.Data[4:], publicKey)

		answer.Len = uint16(len(answer.Data))
		answers = append(answers, answer)
	}

	return answers
}
