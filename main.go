package main

import "dnsrv/dns"

func main() {

	dns.Start(&dns.Config{
		Host: "0.0.0.0",
		Port: 53,
	})

}
