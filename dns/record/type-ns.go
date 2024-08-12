package record

func (r *NS) Encode() []*Answer {
	answers := []*Answer{}

	for _, server := range r.Servers {
		vbytes := encodeDNSName(server)

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
