package dns

import (
	"dnsrv/dns/record"
	"encoding/binary"
	"net"
)

func handle(conn *net.UDPConn, addr *net.UDPAddr, buf []byte) {
	// Parse the query to extract the question name and type
	host, rectype, qlen := parse(buf)

	// Get the client IP address
	ip := addr.IP

	// Resolve the query using the provided resolve function
	entry := resolve(ip, host, rectype)
	ansrs := []*record.Answer{}

	if entry != nil {
		ansrs = entry.Encode()
	}

	// Construct the response DNS header
	header := Header{
		ID:      binary.BigEndian.Uint16(buf[0:2]),
		Flags:   0x8180, // Standard query response, no error
		QDCount: 1,
		ANCount: uint16(len(ansrs)),
		NSCount: 0,
		ARCount: 0,
	}

	// Construct the DNS question section from the request
	question := Question{
		QName:  buf[12 : qlen-4],
		QType:  binary.BigEndian.Uint16(buf[qlen-4 : qlen-2]),
		QClass: binary.BigEndian.Uint16(buf[qlen-2 : qlen]),
	}

	// Create the response packet
	response := response(header, question, ansrs)

	// Send the response
	conn.WriteToUDP(response, addr)
}
