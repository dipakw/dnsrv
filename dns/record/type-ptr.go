package record

func (r *PTR) Encode() []*Answer {
	answers := []*Answer{}

	for _, domain := range r.Domains {
		vbytes := encodeDNSName(domain)

		answer := &Answer{
			Name:  0xC00C,
			Type:  2,
			Class: 1,
			TTL:   r.TTL,
			Len:   uint16(len(vbytes)),
			Data:  vbytes,
		}

		answers = append(answers, answer)
	}

	return answers
}
