package record

import (
	"bytes"
	"encoding/binary"
	"math"
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

func toLOCFormat(degrees, minutes int, seconds float64, hemisphere string) []byte {
	// Convert to total milliseconds of arc
	value := uint32((degrees * 3600 * 1000) + (minutes * 60 * 1000) + int(seconds*1000))
	value |= 0x80000000

	if hemisphere == "S" || hemisphere == "W" {
		value = ^value + 1
	}

	loc := make([]byte, 4)
	binary.BigEndian.PutUint32(loc, value)

	return loc
}

func toLOCAltitude(altitude float64) []byte {
	// Convert altitude to the required LOC format
	altitudeValue := uint32((altitude + 100000) * 100)
	locBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(locBytes, altitudeValue)
	return locBytes
}

func toLOCSizePrecision(value float64) byte {
	exp := 0
	if value > 0 {
		// Adjust the value to fit within the range of 1-9 for the mantissa
		for value > 9 {
			value /= 10
			exp++
		}
		for value < 1 && exp > 0 {
			value *= 10
			exp--
		}
	}

	// Round the mantissa to the nearest integer
	mantissa := uint8(math.Round(value))

	// Combine mantissa and exponent into a single byte
	return (mantissa << 4) | uint8(exp)
}
