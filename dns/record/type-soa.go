package record

import "encoding/binary"

func (r *SOA) Encode() []*Answer {
	name := encodeDNSName(r.Name)
	admn := encodeDNSName(r.Admin)

	answer := &Answer{
		Name:  0xC00C,
		Type:  6,
		Class: 1,
		TTL:   0,
		Data:  make([]byte, len(name)+len(admn)+20),
	}

	offset := 0
	copy(answer.Data[offset:], name)
	offset += len(name)
	copy(answer.Data[offset:], admn)
	offset += len(admn)
	binary.BigEndian.PutUint32(answer.Data[offset:], r.Serial)
	offset += 4
	binary.BigEndian.PutUint32(answer.Data[offset:], r.Refresh)
	offset += 4
	binary.BigEndian.PutUint32(answer.Data[offset:], r.Retry)
	offset += 4
	binary.BigEndian.PutUint32(answer.Data[offset:], r.Expire)
	offset += 4
	binary.BigEndian.PutUint32(answer.Data[offset:], r.Minimum)

	answer.Len = uint16(len(answer.Data))

	return []*Answer{answer}

}
