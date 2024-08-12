package record

import (
	"net"
)

func (r *AAAA) Encode() []*Answer {
	answers := []*Answer{}

	for _, ipv6 := range r.IPv6 {

		answer := &Answer{
			Name:  0xC00C,
			Type:  28,
			Class: 1,
			TTL:   r.TTL,
			Len:   16,
			Data:  net.ParseIP(ipv6).To16(),
		}

		answers = append(answers, answer)

	}

	return answers
}
