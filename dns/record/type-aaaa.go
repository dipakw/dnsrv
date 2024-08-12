package record

import (
	"net"
)

func (r *AAAA) Encode() []*Answer {
	answers := []*Answer{}

	for _, rec := range r.Records {

		answer := &Answer{
			Name:  0xC00C,
			Type:  28,
			Class: 1,
			TTL:   rec.TTL,
			Len:   16,
			Data:  net.ParseIP(rec.IPv6).To16(),
		}

		answers = append(answers, answer)

	}

	return answers
}
