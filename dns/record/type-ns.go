package record

func (r *NS) Encode() []*Answer {
	answers := []*Answer{}

	for _, rec := range r.Records {
		vbytes := encodeDNSName(rec.Server)

		answer := &Answer{
			Name:  0xC00C,
			Type:  2,
			Class: 1,
			TTL:   rec.TTL,
			Len:   uint16(len(vbytes)),
			Data:  vbytes,
		}

		answers = append(answers, answer)
	}

	return answers
}
