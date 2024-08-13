package record

import (
	"encoding/binary"
	"encoding/hex"
)

func (r *DS) Encode() []*Answer {
	answers := []*Answer{}

	for _, rec := range r.Records {
		digest, _ := hex.DecodeString(rec.Digest)

		answer := &Answer{
			Name:  0xC00C,
			Type:  43,
			Class: 1,
			TTL:   rec.TTL,
			Data:  make([]byte, 4+len(digest)),
		}

		binary.BigEndian.PutUint16(answer.Data[0:2], rec.KeyTag)
		answer.Data[2] = rec.Algo
		answer.Data[3] = rec.DigestType
		copy(answer.Data[4:], digest)

		answer.Len = uint16(len(answer.Data))
		answers = append(answers, answer)
	}

	return answers
}
