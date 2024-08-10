package dns

import (
	"bytes"
	"encoding/binary"
	"net"
	"strconv"
	"strings"
)

func response(header Header, question Question, entry *Entry) []byte {
	var buffer bytes.Buffer

	// Write DNS Header
	binary.Write(&buffer, binary.BigEndian, header)

	// Write DNS Question
	buffer.Write(question.QName)
	binary.Write(&buffer, binary.BigEndian, question.QType)
	binary.Write(&buffer, binary.BigEndian, question.QClass)

	// Write DNS Answers
	for _, value := range entry.Values {
		ansData := value

		answer := Answer{
			Name:  0xC00C, // Name offset
			Type:  question.QType,
			Class: question.QClass,
			TTL:   entry.TTL, // TTL in seconds
		}

		switch entry.Type {
		case 1: // A
			answer.Len = 4
			answer.Data = make([]byte, 4)
			binary.BigEndian.PutUint32(answer.Data, inetATon(ansData))
		case 28: // AAAA
			answer.Len = 16
			answer.Data = net.ParseIP(ansData).To16()
		case 16: // TXT
			txtBytes := []byte(ansData)
			answer.Len = uint16(len(txtBytes) + 1)
			answer.Data = append([]byte{uint8(len(txtBytes))}, txtBytes...)
		case 5: // CNAME
			cnameBytes := encodeDNSName(ansData)
			answer.Len = uint16(len(cnameBytes))
			answer.Data = cnameBytes
		case 15: // MX
			mxParts := strings.Fields(ansData)
			preference, _ := strconv.Atoi(mxParts[0])
			mxName := mxParts[1]
			mxBytes := encodeDNSName(mxName)
			answer.Len = uint16(len(mxBytes) + 2)
			answer.Data = make([]byte, 2+len(mxBytes))
			binary.BigEndian.PutUint16(answer.Data[:2], uint16(preference))
			copy(answer.Data[2:], mxBytes)
		case 2: // NS
			nsBytes := encodeDNSName(ansData)
			answer.Len = uint16(len(nsBytes))
			answer.Data = nsBytes
		case 12: // PTR
			ptrBytes := encodeDNSName(ansData)
			answer.Len = uint16(len(ptrBytes))
			answer.Data = ptrBytes
		case 33: // SRV
			srvParts := strings.Fields(ansData)
			priority, _ := strconv.Atoi(srvParts[0])
			weight, _ := strconv.Atoi(srvParts[1])
			port, _ := strconv.Atoi(srvParts[2])
			target := srvParts[3]
			targetBytes := encodeDNSName(target)
			answer.Len = uint16(6 + len(targetBytes))
			answer.Data = make([]byte, 6+len(targetBytes))
			binary.BigEndian.PutUint16(answer.Data[0:2], uint16(priority))
			binary.BigEndian.PutUint16(answer.Data[2:4], uint16(weight))
			binary.BigEndian.PutUint16(answer.Data[4:6], uint16(port))
			copy(answer.Data[6:], targetBytes)
		case 6: // SOA
			soaParts := strings.Fields(ansData)
			mname := encodeDNSName(soaParts[0])
			rname := encodeDNSName(soaParts[1])
			serial, _ := strconv.Atoi(soaParts[2])
			refresh, _ := strconv.Atoi(soaParts[3])
			retry, _ := strconv.Atoi(soaParts[4])
			expire, _ := strconv.Atoi(soaParts[5])
			minimum, _ := strconv.Atoi(soaParts[6])

			soaData := make([]byte, len(mname)+len(rname)+20)
			offset := 0
			copy(soaData[offset:], mname)
			offset += len(mname)
			copy(soaData[offset:], rname)
			offset += len(rname)
			binary.BigEndian.PutUint32(soaData[offset:], uint32(serial))
			offset += 4
			binary.BigEndian.PutUint32(soaData[offset:], uint32(refresh))
			offset += 4
			binary.BigEndian.PutUint32(soaData[offset:], uint32(retry))
			offset += 4
			binary.BigEndian.PutUint32(soaData[offset:], uint32(expire))
			offset += 4
			binary.BigEndian.PutUint32(soaData[offset:], uint32(minimum))

			answer.Len = uint16(len(soaData))
			answer.Data = soaData
		case 257: // CAA
			caaParts := strings.Fields(ansData)
			flag, _ := strconv.Atoi(caaParts[0])
			tag := caaParts[1]
			value := caaParts[2]

			caaData := make([]byte, 2+len(tag)+len(value))
			caaData[0] = uint8(flag)
			caaData[1] = uint8(len(tag))
			copy(caaData[2:], tag)
			copy(caaData[2+len(tag):], value)

			answer.Len = uint16(len(caaData))
			answer.Data = caaData
		case 37: // CERT
			// Simplified handling for CERT records
			certData := []byte(ansData) // In a real implementation, you'd parse the specific fields
			answer.Len = uint16(len(certData))
			answer.Data = certData
		case 48: // DNSKEY
			// Simplified handling for DNSKEY records
			dnskeyData := []byte(ansData) // In a real implementation, you'd parse the specific fields
			answer.Len = uint16(len(dnskeyData))
			answer.Data = dnskeyData
		case 43: // DS
			// Simplified handling for DS records
			dsData := []byte(ansData) // In a real implementation, you'd parse the specific fields
			answer.Len = uint16(len(dsData))
			answer.Data = dsData
		case 65: // HTTPS (similar to SVCB)
			// Handle HTTPS record (could be similar to SVCB)
			httpsData := []byte(ansData) // In a real implementation, you'd parse the specific fields
			answer.Len = uint16(len(httpsData))
			answer.Data = httpsData
		case 29: // LOC
			// Simplified handling for LOC records
			locData := []byte(ansData) // In a real implementation, you'd parse the specific fields
			answer.Len = uint16(len(locData))
			answer.Data = locData
		case 35: // NAPTR
			// Simplified handling for NAPTR records
			naptrData := []byte(ansData) // In a real implementation, you'd parse the specific fields
			answer.Len = uint16(len(naptrData))
			answer.Data = naptrData
		case 53: // SMIMEA
			// Simplified handling for SMIMEA records
			smimeaData := []byte(ansData) // In a real implementation, you'd parse the specific fields
			answer.Len = uint16(len(smimeaData))
			answer.Data = smimeaData
		case 44: // SSHFP
			// Simplified handling for SSHFP records
			sshfpData := []byte(ansData) // In a real implementation, you'd parse the specific fields
			answer.Len = uint16(len(sshfpData))
			answer.Data = sshfpData
		case 64: // SVCB
			// Handle SVCB record
			svcbData := []byte(ansData) // In a real implementation, you'd parse the specific fields
			answer.Len = uint16(len(svcbData))
			answer.Data = svcbData
		case 52: // TLSA
			// Simplified handling for TLSA records
			tlsaData := []byte(ansData) // In a real implementation, you'd parse the specific fields
			answer.Len = uint16(len(tlsaData))
			answer.Data = tlsaData
		case 256: // URI
			// Simplified handling for URI records
			uriData := []byte(ansData) // In a real implementation, you'd parse the specific fields
			answer.Len = uint16(len(uriData))
			answer.Data = uriData
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
