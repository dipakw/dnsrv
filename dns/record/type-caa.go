package record

func (r *CAA) Encode() []*Answer {
	answers := []*Answer{}

	for _, rec := range r.Records {
		tag := []byte(rec.Tag)
		val := []byte(rec.Value)

		answer := &Answer{
			Name:  0xC00C,
			Type:  257,
			Class: 1,
			TTL:   rec.TTL,
			Data:  make([]byte, 2+len(tag)+len(val)),
		}

		answer.Data[0] = rec.Flag
		answer.Data[1] = uint8(len(tag))

		copy(answer.Data[2:], tag)
		copy(answer.Data[2+len(tag):], val)

		answer.Len = uint16(len(answer.Data))

		answers = append(answers, answer)
	}

	return answers
}
