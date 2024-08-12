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
		TTL  uint32
		IPv4 string
	}
}

type AAAA struct {
	Records []struct {
		TTL  uint32
		IPv6 string
	}
}

type TXT struct {
	Records []struct {
		TTL   uint32
		Value string
	}
}

type CNAME struct {
	TTL    uint32
	Target string
}

type MX struct {
	Records []struct {
		TTL      uint32
		Priority uint16
		Server   string
	}
}

type NS struct {
	Records []struct {
		TTL    uint32
		Server string
	}
}

type PTR struct {
	Records []struct {
		TTL    uint32
		Domain string
	}
}

type SRV struct {
	Records []struct {
		TTL      uint32
		Priority uint16
		Weight   uint16
		Port     uint16
		Target   string
	}
}
