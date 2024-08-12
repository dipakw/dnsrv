package record

type Answer struct {
	Name  uint16
	Type  uint16
	Class uint16
	TTL   uint32
	Len   uint16
	Data  []byte
}

// -- RECORD TYPES -- //

type SOA struct {
	Name    string `yaml:"name"`
	Admin   string `yaml:"admin"`
	Serial  uint32 `yaml:"serial"`
	Refresh uint32 `yaml:"refresh"`
	Retry   uint32 `yaml:"retry"`
	Expire  uint32 `yaml:"expire"`
	Minimum uint32 `yaml:"minimum"`
}

type A struct {
	Records []struct {
		TTL  uint32 `yaml:"ttl"`
		IPv4 string `yaml:"ipv4"`
	} `yaml:"records"`
}

type AAAA struct {
	Records []struct {
		TTL  uint32 `yaml:"ttl"`
		IPv6 string `yaml:"ipv6"`
	} `yaml:"records"`
}

type TXT struct {
	Records []struct {
		TTL   uint32 `yaml:"ttl"`
		Value string `yaml:"value"`
	} `yaml:"records"`
}

type CNAME struct {
	TTL    uint32 `yaml:"ttl"`
	Target string `yaml:"target"`
}

type MX struct {
	Records []struct {
		TTL      uint32 `yaml:"ttl"`
		Priority uint16 `yaml:"priority"`
		Server   string `yaml:"server"`
	} `yaml:"records"`
}

type NS struct {
	Records []struct {
		TTL    uint32 `yaml:"ttl"`
		Server string `yaml:"server"`
	} `yaml:"records"`
}

type PTR struct {
	Records []struct {
		TTL    uint32 `yaml:"ttl"`
		Domain string `yaml:"domain"`
	} `yaml:"records"`
}

type SRV struct {
	Records []struct {
		TTL      uint32 `yaml:"ttl"`
		Priority uint16 `yaml:"priority"`
		Weight   uint16 `yaml:"weight"`
		Port     uint16 `yaml:"port"`
		Target   string `yaml:"target"`
	} `yaml:"records"`
}
