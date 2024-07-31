package dns

import (
	"log"
	"net"
)

func Start() {

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

		go handle(conn, clientAddr, buf[:n])
	}

}
