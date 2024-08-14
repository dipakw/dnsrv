package record

func (r *LOC) Encode() []*Answer {
	answers := []*Answer{}

	for _, rec := range r.Records {
		answer := &Answer{
			Name:  0xC00C,
			Type:  29,
			Class: 1,
			TTL:   rec.TTL,
			Len:   16,
			Data:  make([]byte, 16),
		}

		siz := toLOCSizePrecision(rec.Prec.Size * 100)
		hor := toLOCSizePrecision(rec.Prec.Horz * 100)
		vrt := toLOCSizePrecision(rec.Prec.Vert * 100)
		lat := toLOCFormat(rec.Lat.Deg, rec.Lat.Min, rec.Lat.Sec, rec.Lat.Hem)
		lon := toLOCFormat(rec.Lon.Deg, rec.Lon.Min, rec.Lon.Sec, rec.Lon.Hem)
		alt := toLOCAltitude(rec.Prec.Alt)

		answer.Data[0] = 0x00 // Version
		answer.Data[1] = siz
		answer.Data[2] = hor
		answer.Data[3] = vrt

		copy(answer.Data[4:8], lat)
		copy(answer.Data[8:12], lon)
		copy(answer.Data[12:16], alt)

		answers = append(answers, answer)
	}

	return answers
}
