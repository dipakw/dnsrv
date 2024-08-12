package record

import "encoding/binary"

func (r *MX) Encode() []*Answer {
	answers := []*Answer{}

	for _, rec := range r.Records {
		answer := &Answer{
			Name:  0xC00C,
			Type:  15,
			Class: 1,
			TTL:   r.TTL,
		}

		mxBytes := encodeDNSName(rec.Server)
		answer.Len = uint16(len(mxBytes) + 2)
		answer.Data = make([]byte, 2+len(mxBytes))
		binary.BigEndian.PutUint16(answer.Data[:2], uint16(rec.Priority))
		copy(answer.Data[2:], mxBytes)

		answers = append(answers, answer)
	}

	return answers
}
