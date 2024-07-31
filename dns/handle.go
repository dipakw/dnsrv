package dns

import (
	"encoding/binary"
	"net"
)

func handle(conn *net.UDPConn, addr *net.UDPAddr, buf []byte) {
	// Parse the query to extract the question name and type
	qname, qtype, qlen := parse(buf)

	// Resolve the query using the provided resolve function
	records := resolve(qtype, qname)

	// Construct the response DNS header
	header := Header{
		ID:      binary.BigEndian.Uint16(buf[0:2]),
		Flags:   0x8180, // Standard query response, no error
		QDCount: 1,
		ANCount: uint16(len(records)),
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
	response := response(header, question, records)

	// Send the response
	conn.WriteToUDP(response, addr)
}
