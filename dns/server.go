package dns

import (
	"log"
	"net"
)

func Start(conf *Config) {

	conf.Load()

	addr := net.UDPAddr{
		Port: conf.Port,
		IP:   net.ParseIP(conf.Host),
	}

	conn, err := net.ListenUDP("udp", &addr)

	if err != nil {
		log.Fatalf("Failed to start: %v", err)
	}

	defer conn.Close()

	log.Println("Started ..")

	for {
		buf := make([]byte, 512)
		n, addr, err := conn.ReadFromUDP(buf)

		if err != nil {
			log.Printf("Failed to read from UDP: %v", err)
			continue
		}

		go handle(conn, addr, buf[:n])
	}

}
