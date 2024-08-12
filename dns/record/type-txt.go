package record

func (r *TXT) Encode() []*Answer {
	answers := []*Answer{}

	for _, rec := range r.Records {
		vbytes := []byte(rec.Value)

		answer := &Answer{
			Name:  0xC00C,
			Type:  16,
			Class: 1,
			TTL:   rec.TTL,
			Len:   uint16(len(vbytes) + 1),
			Data:  append([]byte{uint8(len(vbytes))}, vbytes...),
		}

		answers = append(answers, answer)
	}

	return answers
}
