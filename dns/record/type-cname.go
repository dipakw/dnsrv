package record

func (r *CNAME) Encode() []*Answer {
	answrs := []*Answer{}
	vbytes := encodeDNSName(r.Target)

	answer := &Answer{
		Name:  0xC00C,
		Type:  5,
		Class: 1,
		TTL:   r.TTL,
		Len:   uint16(len(vbytes)),
		Data:  vbytes,
	}

	answrs = append(answrs, answer)

	return answrs
}
