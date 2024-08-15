package record

import (
	"encoding/binary"
)

func (r *SRV) Encode() []*Answer {
	answers := []*Answer{}

	for _, rec := range r.Records {
		tbytes := encodeDNSName(rec.Target)

		answer := &Answer{
			Name:  0xC00C,
			Type:  33,
			Class: 1,
			TTL:   rec.TTL,
			Len:   uint16(6 + len(tbytes)),
			Data:  make([]byte, 6+len(tbytes)),
		}

		binary.BigEndian.PutUint16(answer.Data[0:2], rec.Priority)
		binary.BigEndian.PutUint16(answer.Data[2:4], rec.Weight)
		binary.BigEndian.PutUint16(answer.Data[4:6], rec.Port)
		copy(answer.Data[6:], tbytes)

		answers = append(answers, answer)
	}

	return answers
}
