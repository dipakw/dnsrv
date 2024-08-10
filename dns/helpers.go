package dns

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"strings"
)

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

// Convert an IP string to a uint32
func inetATon(ip string) uint32 {
	var intIP uint32
	octets := strings.Split(ip, ".")

	for _, octet := range octets {
		val, _ := strconv.Atoi(octet)
		intIP = intIP<<8 + uint32(val)
	}

	return intIP
}

func toLOCFormat(degrees, minutes int, seconds float64, hemisphere string) []byte {
	// Convert latitude/longitude to the required LOC format
	value := uint32((degrees * 3600 * 1000) + (minutes * 60 * 1000) + int(seconds*1000))
	if hemisphere == "S" || hemisphere == "W" {
		value = 0x80000000 | value // Set the MSB for south/west hemispheres
	}
	locBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(locBytes, value)
	return locBytes
}

func toLOCAltitude(altitude float64) []byte {
	// Convert altitude to the required LOC format
	altitudeValue := uint32((altitude + 100000) * 100)
	locBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(locBytes, altitudeValue)
	return locBytes
}

func toLOCSizePrecision(value float64) []byte {
	// Convert size/precision to the required LOC format
	exp := 0
	if value > 0 {
		for value > 9 {
			value /= 10
			exp++
		}
	}
	mantissa := uint8(value)
	return []byte{(mantissa << 4) | uint8(exp)}
}
