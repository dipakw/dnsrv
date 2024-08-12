package record

import "encoding/binary"

func (r *A) Encode() []*Answer {
	answers := []*Answer{}

	for _, ipv4 := range r.IPv4 {

		answer := &Answer{
			Name:  0xC00C,
			Type:  1,
			Class: 1,
			TTL:   r.TTL,
			Len:   4,
			Data:  make([]byte, 4),
		}

		binary.BigEndian.PutUint32(answer.Data, inetATon(ipv4))

		answers = append(answers, answer)

	}

	return answers
}
