package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
)

// resolve function to handle multiple record types
func resolve(qtype uint16, qname string) []string {
	switch qname {
	case "www.example.com":
		switch qtype {
		case 1:
			return []string{"A 122.34.56.6"}
		case 28:
			return []string{"AAAA 2001:0db8:85a3:0000:0000:8a2e:0370:7334"}
		case 16:
			return []string{"TXT v=spf1 include:_spf.example.com ~all"}
		case 5:
			return []string{"CNAME example.com"}
		case 15:
			return []string{
				"MX 10 mail1.example.com",
				"MX 20 mail2.example.com",
				"MX 50 mail3.example.com",
			}
		case 2:
			return []string{"NS ns1.example.com"}
		case 12:
			return []string{"PTR ptr.example.com"}
		case 33:
			return []string{"SRV 0 5 5060 sip.example.com"}
		}
	}
	return []string{}
}

// DNSHeader represents the DNS header structure
type DNSHeader struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

// DNSQuestion represents a DNS question
type DNSQuestion struct {
	QName  []byte
	QType  uint16
	QClass uint16
}

// DNSAnswer represents a DNS answer
type DNSAnswer struct {
	Name  uint16
	Type  uint16
	Class uint16
	TTL   uint32
	Len   uint16
	Data  []byte
}

// parseQuery extracts the query name and type from the DNS request
func parseQuery(packet []byte) (string, uint16, int) {
	var qname string
	i := 12
	for {
		length := int(packet[i])
		if length == 0 {
			break
		}
		if i != 12 {
			qname += "."
		}
		qname += string(packet[i+1 : i+1+length])
		i += length + 1
	}
	qtype := binary.BigEndian.Uint16(packet[i+1 : i+3])
	// 16 bytes header + qname + 2 bytes type + 2 bytes class
	return qname, qtype, i + 5
}

// buildResponse creates the DNS response packet
func buildResponse(header DNSHeader, question DNSQuestion, records []string) []byte {
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

		answer := DNSAnswer{
			Name:  0xC00C, // Name offset
			Type:  question.QType,
			Class: question.QClass,
			TTL:   30, // TTL in seconds
		}

		switch recordType {
		case "A":
			answer.Len = 4
			answer.Data = make([]byte, 4)
			binary.BigEndian.PutUint32(answer.Data, inet_aton(recordData))
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

// encodeDNSName converts a domain name to DNS format
func encodeDNSName(name string) []byte {
	parts := strings.Split(name, ".")
	var buffer bytes.Buffer
	for _, part := range parts {
		buffer.WriteByte(uint8(len(part)))
		buffer.WriteString(part)
	}
	buffer.WriteByte(0)
	return buffer.Bytes()
}

// inet_aton converts an IP string to a uint32
func inet_aton(ip string) uint32 {
	var intIP uint32
	octets := strings.Split(ip, ".")
	for _, octet := range octets {
		val, _ := strconv.Atoi(octet)
		intIP = intIP<<8 + uint32(val)
	}
	return intIP
}

func handleRequest(conn *net.UDPConn, addr *net.UDPAddr, buf []byte) {
	// Parse the query to extract the question name and type
	qname, qtype, qlen := parseQuery(buf)

	// Resolve the query using the provided resolve function
	records := resolve(qtype, qname)

	// Construct the response DNS header
	header := DNSHeader{
		ID:      binary.BigEndian.Uint16(buf[0:2]),
		Flags:   0x8180, // Standard query response, no error
		QDCount: 1,
		ANCount: uint16(len(records)),
		NSCount: 0,
		ARCount: 0,
	}

	// Construct the DNS question section from the request
	question := DNSQuestion{
		QName:  buf[12 : qlen-4],
		QType:  binary.BigEndian.Uint16(buf[qlen-4 : qlen-2]),
		QClass: binary.BigEndian.Uint16(buf[qlen-2 : qlen]),
	}

	// Create the response packet
	response := buildResponse(header, question, records)

	fmt.Println("FROM:", addr.String())

	// Send the response
	conn.WriteToUDP(response, addr)
}

func main() {
	addr := net.UDPAddr{
		Port: 53,
		IP:   net.ParseIP("0.0.0.0"),
	}

	conn, err := net.ListenUDP("udp", &addr)

	if err != nil {
		log.Fatalf("Failed to set up UDP listener: %v", err)
	}

	defer conn.Close()

	log.Println("DNS server is up and running...")

	for {
		buf := make([]byte, 512)
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("Failed to read from UDP: %v", err)
			continue
		}

		go handleRequest(conn, clientAddr, buf[:n])
	}
}
