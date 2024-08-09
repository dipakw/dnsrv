package main

import "dnsrv/dns"

func main() {

	config := &dns.Config{
		Host:  "0.0.0.0",
		Port:  53,
		Zones: []string{"./zones.d"},
	}

	dns.Start(config)

}
