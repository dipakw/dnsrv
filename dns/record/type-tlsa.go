package record

import "encoding/hex"

func (r *TLSA) Encode() []*Answer {
	answers := []*Answer{}

	for _, rec := range r.Records {
		cert, _ := hex.DecodeString(rec.Cert)

		answer := &Answer{
			Name:  0xC00C,
			Type:  52,
			Class: 1,
			TTL:   rec.TTL,
			Data:  make([]byte, 3+len(cert)),
		}

		answer.Data[0] = rec.Usage
		answer.Data[1] = rec.Selector
		answer.Data[2] = rec.Match

		copy(answer.Data[3:], cert)

		answer.Len = uint16(len(answer.Data))
		answers = append(answers, answer)
	}

	return answers
}
