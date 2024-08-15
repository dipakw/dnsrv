package record

import "encoding/hex"

func (r *SSHFP) Encode() []*Answer {
	answers := []*Answer{}

	for _, rec := range r.Records {
		fingerprint, _ := hex.DecodeString(rec.Fingerprint)

		answer := &Answer{
			Name:  0xC00C,
			Type:  44,
			Class: 1,
			TTL:   rec.TTL,
			Data:  make([]byte, 2+len(fingerprint)),
		}

		answer.Data[0] = rec.Algo
		answer.Data[1] = rec.Type

		copy(answer.Data[2:], fingerprint)

		answer.Len = uint16(len(answer.Data))
		answers = append(answers, answer)
	}

	return answers
}
