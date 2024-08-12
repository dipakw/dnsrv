package record

import "encoding/binary"

func (r *A) Encode() []*Answer {
	answers := []*Answer{}

	for _, rec := range r.Records {

		answer := &Answer{
			Name:  0xC00C,
			Type:  1,
			Class: 1,
			TTL:   rec.TTL,
			Len:   4,
			Data:  make([]byte, 4),
		}

		binary.BigEndian.PutUint32(answer.Data, inetATon(rec.IPv4))

		answers = append(answers, answer)

	}

	return answers
}
