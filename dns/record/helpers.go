package record

import (
	"bytes"
	"encoding/binary"
	"math"
	"regexp"
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
	if name == "" || name == "." {
		return []byte{byte(0)}
	}

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

func getKeyId(key string) ([]byte, bool) {
	switch key {
	case "alpn":
		return []byte{0x00, 0x01}, true
	case "ipv4hint":
		return []byte{0x00, 0x04}, true
	case "ipv6hint":
		return []byte{0x00, 0x06}, true
	case "mandatory":
		return []byte{0x00, 0x00}, true
	case "no-default-alpn":
		return []byte{0x00, 0x02}, true
	case "port":
		return []byte{0x00, 0x03}, true
	case "dohpath":
		return []byte{0x00, 0x07}, true
	}

	regx := regexp.MustCompile(`^key([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-4])$`)

	if regx.MatchString(key) {
		num, err := strconv.Atoi(key[3:])

		if err == nil && num > 7 {
			return intTo2Bytes(num), true
		}
	}

	return []byte{}, false
}

func intTo2Bytes(n int) []byte {
	return []byte{
		byte(n >> 8),   // Most significant byte
		byte(n & 0xFF), // Least significant byte
	}
}
