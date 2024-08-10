package dns

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
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
			certParts := strings.Split(ansData, ",")
			certType, _ := strconv.Atoi(certParts[0])
			keyTag, _ := strconv.Atoi(certParts[1])
			algorithm, _ := strconv.Atoi(certParts[2])
			certificate := []byte(certParts[3])

			certData := make([]byte, 5+len(certificate))
			binary.BigEndian.PutUint16(certData[0:2], uint16(certType))
			binary.BigEndian.PutUint16(certData[2:4], uint16(keyTag))
			certData[4] = uint8(algorithm)
			copy(certData[5:], certificate)

			answer.Len = uint16(len(certData))
			answer.Data = certData
		case 48: // DNSKEY
			dnskeyParts := strings.Split(ansData, " ")
			flags, _ := strconv.Atoi(dnskeyParts[0])
			protocol, _ := strconv.Atoi(dnskeyParts[1])
			algorithm, _ := strconv.Atoi(dnskeyParts[2])
			publicKey := []byte(dnskeyParts[3])

			dnskeyData := make([]byte, 4+len(publicKey))
			binary.BigEndian.PutUint16(dnskeyData[0:2], uint16(flags))
			dnskeyData[2] = uint8(protocol)
			dnskeyData[3] = uint8(algorithm)
			copy(dnskeyData[4:], publicKey)

			answer.Len = uint16(len(dnskeyData))
			answer.Data = dnskeyData
		case 43: // DS
			dsParts := strings.Split(ansData, " ")
			keyTag, _ := strconv.Atoi(dsParts[0])
			algorithm, _ := strconv.Atoi(dsParts[1])
			digestType, _ := strconv.Atoi(dsParts[2])
			digest := []byte(dsParts[3])

			dsData := make([]byte, 4+len(digest))
			binary.BigEndian.PutUint16(dsData[0:2], uint16(keyTag))
			dsData[2] = uint8(algorithm)
			dsData[3] = uint8(digestType)
			copy(dsData[4:], digest)

			answer.Len = uint16(len(dsData))
			answer.Data = dsData
		case 65: // HTTPS
			// Example ansData: "1 example.com alpn=h2,h3"

			// Split ansData into the priority, target, and parameters
			parts := strings.SplitN(ansData, " ", 3)

			// Parse the priority
			priority, _ := strconv.Atoi(parts[0])

			// Parse the target DNS name
			target := parts[1]
			targetBytes := encodeDNSName(target)

			// Parse the parameters
			params := parts[2] // "alpn=h2,h3"
			paramParts := strings.Split(params, ",")

			// Construct the binary representation of the parameters
			var paramBytes []byte
			for _, param := range paramParts {
				kv := strings.SplitN(param, "=", 2)
				key := kv[0]
				value := kv[1]

				switch key {
				case "alpn":
					// ALPN protocol names are encoded as a length byte followed by the protocol string
					valueBytes := []byte(value)
					paramBytes = append(paramBytes, 0x00, 0x01) // ALPN key = 1
					paramBytes = append(paramBytes, uint8(len(valueBytes)))
					paramBytes = append(paramBytes, valueBytes...)
					// Add more cases as needed for other parameters like ipv4hint, esniconfig, etc.
				}
			}

			// Construct the final HTTPS data
			httpsData := make([]byte, 2+len(targetBytes)+len(paramBytes))
			binary.BigEndian.PutUint16(httpsData[0:2], uint16(priority)) // Priority
			copy(httpsData[2:], targetBytes)                             // Target name
			copy(httpsData[2+len(targetBytes):], paramBytes)             // Parameters

			answer.Len = uint16(len(httpsData))
			answer.Data = httpsData
		case 29: // LOC
			// Example ansData: "52 22 17.018 N 4 53 26.322 E 0.00m 2m 10000m 10m"

			parts := strings.Fields(ansData)

			// Parse latitude
			latDegrees, _ := strconv.Atoi(parts[0])
			latMinutes, _ := strconv.Atoi(parts[1])
			latSeconds, _ := strconv.ParseFloat(parts[2], 64)
			latHemisphere := parts[3]

			// Parse longitude
			lonDegrees, _ := strconv.Atoi(parts[4])
			lonMinutes, _ := strconv.Atoi(parts[5])
			lonSeconds, _ := strconv.ParseFloat(parts[6], 64)
			lonHemisphere := parts[7]

			// Parse altitude, size, horizontal precision, and vertical precision
			altitude, _ := strconv.ParseFloat(strings.TrimSuffix(parts[8], "m"), 64)
			size, _ := strconv.ParseFloat(strings.TrimSuffix(parts[9], "m"), 64)
			hPrecision, _ := strconv.ParseFloat(strings.TrimSuffix(parts[10], "m"), 64)
			vPrecision, _ := strconv.ParseFloat(strings.TrimSuffix(parts[11], "m"), 64)

			// Convert latitude and longitude to LOC format
			lat := toLOCFormat(latDegrees, latMinutes, latSeconds, latHemisphere)
			lon := toLOCFormat(lonDegrees, lonMinutes, lonSeconds, lonHemisphere)

			// Convert altitude, size, and precision to LOC format
			altitudeBytes := toLOCAltitude(altitude)
			sizeBytes := toLOCSizePrecision(size)
			hPrecisionBytes := toLOCSizePrecision(hPrecision)
			vPrecisionBytes := toLOCSizePrecision(vPrecision)

			// Construct the final LOC data
			locData := make([]byte, 16)
			copy(locData[0:4], lat)
			copy(locData[4:8], lon)
			copy(locData[8:12], altitudeBytes)
			copy(locData[12:13], sizeBytes)
			copy(locData[13:14], hPrecisionBytes)
			copy(locData[14:15], vPrecisionBytes)

			answer.Len = uint16(len(locData))
			answer.Data = locData
		case 35: // NAPTR
			naptrParts := strings.Split(ansData, " ")
			order, _ := strconv.Atoi(naptrParts[0])
			preference, _ := strconv.Atoi(naptrParts[1])
			flags := naptrParts[2]
			service := naptrParts[3]
			regexp := naptrParts[4]
			replacement := encodeDNSName(naptrParts[5])

			naptrData := make([]byte, 4+len(flags)+len(service)+len(regexp)+len(replacement)+5)
			binary.BigEndian.PutUint16(naptrData[0:2], uint16(order))
			binary.BigEndian.PutUint16(naptrData[2:4], uint16(preference))
			naptrData[4] = uint8(len(flags))
			copy(naptrData[5:], flags)
			offset := 5 + len(flags)
			naptrData[offset] = uint8(len(service))
			copy(naptrData[offset+1:], service)
			offset += 1 + len(service)
			naptrData[offset] = uint8(len(regexp))
			copy(naptrData[offset+1:], regexp)
			offset += 1 + len(regexp)
			copy(naptrData[offset+1:], replacement)

			answer.Len = uint16(len(naptrData))
			answer.Data = naptrData
		case 53: // SMIMEA
			// Example ansData: "3 1 1 aabbccddeeff..."

			// Split ansData into usage, selector, matching type, and certificate association data
			parts := strings.SplitN(ansData, " ", 4)

			// Parse the usage
			usage, _ := strconv.Atoi(parts[0])

			// Parse the selector
			selector, _ := strconv.Atoi(parts[1])

			// Parse the matching type
			matchingType, _ := strconv.Atoi(parts[2])

			// Parse the certificate association data (usually in hexadecimal format)
			certificateAssocData, _ := hex.DecodeString(parts[3])

			// Construct the final SMIMEA data
			smimeaData := make([]byte, 3+len(certificateAssocData))
			smimeaData[0] = uint8(usage)               // Usage
			smimeaData[1] = uint8(selector)            // Selector
			smimeaData[2] = uint8(matchingType)        // Matching Type
			copy(smimeaData[3:], certificateAssocData) // Certificate Association Data

			answer.Len = uint16(len(smimeaData))
			answer.Data = smimeaData
		case 44: // SSHFP
			sshfpParts := strings.Split(ansData, " ")
			algorithm, _ := strconv.Atoi(sshfpParts[0])
			fpType, _ := strconv.Atoi(sshfpParts[1])
			fingerprint := []byte(sshfpParts[2])

			sshfpData := make([]byte, 2+len(fingerprint))
			sshfpData[0] = uint8(algorithm)
			sshfpData[1] = uint8(fpType)
			copy(sshfpData[2:], fingerprint)

			answer.Len = uint16(len(sshfpData))
			answer.Data = sshfpData
		case 64: // SVCB
			// Example ansData: "1 example.com alpn=h2,ipv4hint=192.0.2.1,192.0.2.2"

			// Split ansData into the priority, target, and parameters
			parts := strings.SplitN(ansData, " ", 3)

			// Parse the priority
			priority, _ := strconv.Atoi(parts[0])

			// Parse the target DNS name
			target := parts[1]
			targetBytes := encodeDNSName(target)

			// Parse the parameters
			params := parts[2] // "alpn=h2,ipv4hint=192.0.2.1,192.0.2.2"
			paramParts := strings.Split(params, ",")

			// Construct the binary representation of the parameters
			var paramBytes []byte
			for _, param := range paramParts {
				kv := strings.SplitN(param, "=", 2)
				key := kv[0]
				value := kv[1]

				switch key {
				case "alpn":
					// ALPN protocol names are encoded as a length byte followed by the protocol string
					valueBytes := []byte(value)
					paramBytes = append(paramBytes, 0x00, 0x01) // ALPN key = 1
					paramBytes = append(paramBytes, uint8(len(valueBytes)))
					paramBytes = append(paramBytes, valueBytes...)
				case "ipv4hint":
					// IPv4 Hint is a series of 4-byte addresses
					ipList := strings.Split(value, ",")
					for _, ip := range ipList {
						ipBytes := net.ParseIP(ip).To4()
						paramBytes = append(paramBytes, 0x00, 0x04) // IPv4 Hint key = 4
						paramBytes = append(paramBytes, ipBytes...)
					}
					// Add more cases as needed for other parameters
				}
			}

			// Construct the final SVCB data
			svcbData := make([]byte, 2+len(targetBytes)+len(paramBytes))
			binary.BigEndian.PutUint16(svcbData[0:2], uint16(priority)) // Priority
			copy(svcbData[2:], targetBytes)                             // Target name
			copy(svcbData[2+len(targetBytes):], paramBytes)             // Parameters

			answer.Len = uint16(len(svcbData))
			answer.Data = svcbData
		case 52: // TLSA
			tlsaParts := strings.Split(ansData, " ")
			usage, _ := strconv.Atoi(tlsaParts[0])
			selector, _ := strconv.Atoi(tlsaParts[1])
			matchingType, _ := strconv.Atoi(tlsaParts[2])
			certificateAssocData := []byte(tlsaParts[3])

			tlsaData := make([]byte, 3+len(certificateAssocData))
			tlsaData[0] = uint8(usage)
			tlsaData[1] = uint8(selector)
			tlsaData[2] = uint8(matchingType)
			copy(tlsaData[3:], certificateAssocData)

			answer.Len = uint16(len(tlsaData))
			answer.Data = tlsaData
		case 256: // URI
			uriParts := strings.Fields(ansData)
			priority, _ := strconv.Atoi(uriParts[0])
			weight, _ := strconv.Atoi(uriParts[1])
			uriTarget := uriParts[2]

			uriData := make([]byte, 4+len(uriTarget))
			binary.BigEndian.PutUint16(uriData[0:2], uint16(priority))
			binary.BigEndian.PutUint16(uriData[2:4], uint16(weight))
			copy(uriData[4:], uriTarget)

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
