package record

import (
	"bytes"
	"encoding/binary"
)

func (r *NAPTR) Encode() []*Answer {
	answers := []*Answer{}

	for _, rec := range r.Records {
		flags := []byte(rec.Flags)
		servc := []byte(rec.Service)
		regex := []byte(rec.RegEx)
		replc := encodeDNSName(rec.Replace)

		answer := &Answer{
			Name:  0xC00C,
			Type:  35,
			Class: 1,
			TTL:   rec.TTL,
		}

		var data bytes.Buffer

		binary.Write(&data, binary.BigEndian, rec.Order)
		binary.Write(&data, binary.BigEndian, rec.Pref)
		data.WriteByte(uint8(len(flags)))
		data.Write(flags)
		data.WriteByte(uint8(len(servc)))
		data.Write(servc)
		data.WriteByte(uint8(len(regex)))
		data.Write(regex)
		data.Write(replc)

		answer.Data = data.Bytes()
		answer.Len = uint16(len(answer.Data))

		answers = append(answers, answer)
	}

	return answers
}
