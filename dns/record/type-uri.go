package record

import (
	"encoding/binary"
)

func (r *URI) Encode() []*Answer {
	answers := []*Answer{}

	for _, rec := range r.Records {
		tbytes := []byte(rec.Target)

		answer := &Answer{
			Name:  0xC00C,
			Type:  256,
			Class: 1,
			TTL:   rec.TTL,
			Len:   uint16(4 + len(tbytes)),
			Data:  make([]byte, 4+len(tbytes)),
		}

		binary.BigEndian.PutUint16(answer.Data[0:2], uint16(rec.Priority))
		binary.BigEndian.PutUint16(answer.Data[2:4], uint16(rec.Weight))
		copy(answer.Data[4:], tbytes)

		answers = append(answers, answer)
	}

	return answers
}
