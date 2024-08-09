package dns

type Config struct {
	Host  string
	Port  int
	Zones []string
}

type Header struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

type Question struct {
	QName  []byte
	QType  uint16
	QClass uint16
}

type Answer struct {
	Name  uint16
	Type  uint16
	Class uint16
	TTL   uint32
	Len   uint16
	Data  []byte
}

// -- FOR ZONE FILE -- //

type SOA struct {
	Name    string `yaml:"name"`
	Admin   string `yaml:"admin"`
	Serial  uint32 `yaml:"serial"`
	Refresh uint32 `yaml:"refresh"`
	Retry   uint32 `yaml:"retry"`
	Expire  uint32 `yaml:"expire"`
	Minimum uint32 `yaml:"minimum"`
}

type Entry struct {
	TTL    uint32   `yaml:"ttl"`
	Values []string `yaml:"values"`
	Type   uint16   `yaml:"-"`
}

type Record struct {
	Default *Entry            `yaml:"default"`
	Regions map[string]*Entry `yaml:"regions"`
}

type Records struct {
	SOA   *SOA               `yaml:"SOA"`
	NS    map[string]*Record `yaml:"NS"`
	A     map[string]*Record `yaml:"A"`
	AAAA  map[string]*Record `yaml:"AAAA"`
	TXT   map[string]*Record `yaml:"TXT"`
	CNAME map[string]*Record `yaml:"CNAME"`
	MX    map[string]*Record `yaml:"MX"`
	PTR   map[string]*Record `yaml:"PTR"`
	SRV   map[string]*Record `yaml:"SRV"`
}

type Zone struct {
	Zone    string   `yaml:"zone"`
	Records *Records `yaml:"records"`
}
