package dns

import (
	"bytes"
	"encoding/binary"
	"net"
	"strconv"
	"strings"
)

func response(header Header, question Question, records []string) []byte {
	var buffer bytes.Buffer

	// Write DNS Header
	binary.Write(&buffer, binary.BigEndian, header)

	// Write DNS Question
	buffer.Write(question.QName)
	binary.Write(&buffer, binary.BigEndian, question.QType)
	binary.Write(&buffer, binary.BigEndian, question.QClass)

	// Write DNS Answers
	for _, record := range records {
		parts := strings.Fields(record)
		recordType := parts[0]
		recordData := strings.Join(parts[1:], " ")

		answer := Answer{
			Name:  0xC00C, // Name offset
			Type:  question.QType,
			Class: question.QClass,
			TTL:   0, // TTL in seconds
		}

		switch recordType {
		case "A":
			answer.Len = 4
			answer.Data = make([]byte, 4)
			binary.BigEndian.PutUint32(answer.Data, inetATon(recordData))
		case "AAAA":
			answer.Len = 16
			answer.Data = net.ParseIP(recordData).To16()
		case "TXT":
			txtBytes := []byte(recordData)
			answer.Len = uint16(len(txtBytes) + 1)
			answer.Data = append([]byte{uint8(len(txtBytes))}, txtBytes...)
		case "CNAME":
			cnameBytes := encodeDNSName(recordData)
			answer.Len = uint16(len(cnameBytes))
			answer.Data = cnameBytes
		case "MX":
			parts := strings.Fields(recordData)
			preference, _ := strconv.Atoi(parts[0])
			mxName := parts[1]
			mxBytes := encodeDNSName(mxName)
			answer.Len = uint16(len(mxBytes) + 2)
			answer.Data = make([]byte, 2+len(mxBytes))
			binary.BigEndian.PutUint16(answer.Data[:2], uint16(preference))
			copy(answer.Data[2:], mxBytes)
		case "NS":
			nsBytes := encodeDNSName(recordData)
			answer.Len = uint16(len(nsBytes))
			answer.Data = nsBytes
		case "PTR":
			ptrBytes := encodeDNSName(recordData)
			answer.Len = uint16(len(ptrBytes))
			answer.Data = ptrBytes
		case "SRV":
			parts := strings.Fields(recordData)
			priority, _ := strconv.Atoi(parts[0])
			weight, _ := strconv.Atoi(parts[1])
			port, _ := strconv.Atoi(parts[2])
			target := parts[3]
			targetBytes := encodeDNSName(target)
			answer.Len = uint16(6 + len(targetBytes))
			answer.Data = make([]byte, 6+len(targetBytes))
			binary.BigEndian.PutUint16(answer.Data[0:2], uint16(priority))
			binary.BigEndian.PutUint16(answer.Data[2:4], uint16(weight))
			binary.BigEndian.PutUint16(answer.Data[4:6], uint16(port))
			copy(answer.Data[6:], targetBytes)
		}

		binary.Write(&buffer, binary.BigEndian, answer.Name)
		binary.Write(&buffer, binary.BigEndian, answer.Type)
		binary.Write(&buffer, binary.BigEndian, answer.Class)
		binary.Write(&buffer, binary.BigEndian, answer.TTL)
		binary.Write(&buffer, binary.BigEndian, answer.Len)
		buffer.Write(answer.Data)
	}

	return buffer.Bytes()
}
