package record

import (
	"bytes"
	"strconv"
	"strings"
)

func inetATon(ip string) uint32 {
	var intIP uint32
	octets := strings.Split(ip, ".")

	for _, octet := range octets {
		val, _ := strconv.Atoi(octet)
		intIP = intIP<<8 + uint32(val)
	}

	return intIP
}

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

func encodeName(name string) []byte {
	parts := strings.Split(name, ".")
	var buffer bytes.Buffer

	for _, part := range parts {
		buffer.WriteByte(uint8(len(part)))
		buffer.Write([]byte(part))
	}

	return buffer.Bytes()
}
