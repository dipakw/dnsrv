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
	IPv4 []string
	TTL  uint32
}

type AAAA struct {
	IPv6 []string
	TTL  uint32
}

type TXT struct {
	Values []string
	TTL    uint32
}

type CNAME struct {
	Target string
	TTL    uint32
}

type MX struct {
	TTL uint32

	Records []struct {
		Priority uint16
		Server   string
	}
}

type NS struct {
	TTL     uint32
	Servers []string
}

type PTR struct {
	TTL     uint32
	Domains []string
}
