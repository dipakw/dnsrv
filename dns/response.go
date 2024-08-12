package dns

import (
	"bytes"
	"dnsrv/dns/record"
	"encoding/binary"
)

func response(header Header, question Question, answers []*record.Answer) []byte {
	var buffer bytes.Buffer

	// Write DNS Header
	binary.Write(&buffer, binary.BigEndian, header)

	// Write DNS Question
	buffer.Write(question.QName)
	binary.Write(&buffer, binary.BigEndian, question.QType)
	binary.Write(&buffer, binary.BigEndian, question.QClass)

	// Write DNS Answers
	for _, answer := range answers {
		binary.Write(&buffer, binary.BigEndian, answer.Name)
		binary.Write(&buffer, binary.BigEndian, answer.Type)
		binary.Write(&buffer, binary.BigEndian, answer.Class)
		binary.Write(&buffer, binary.BigEndian, answer.TTL)
		binary.Write(&buffer, binary.BigEndian, answer.Len)
		buffer.Write(answer.Data)
	}

	return buffer.Bytes()
}
