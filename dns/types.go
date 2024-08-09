package dns

type Config struct {
	Host  string
	Port  int
	Zones string
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
	Name    string
	Admin   string
	Serial  uint32
	Refresh uint32
	Retry   uint32
	Expire  uint32
	Minimum uint32
}

type Entry struct {
	TTL    uint32
	Values []string
}

type Record struct {
	Default *Entry
	Regions map[string]*Entry
}

type Records struct {
	SOA   *SOA
	NS    map[string]*Record
	A     map[string]*Record
	AAAA  map[string]*Record
	TXT   map[string]*Record
	CNAME map[string]*Record
	MX    map[string]*Record
	PTR   map[string]*Record
	SRV   map[string]*Record
}

type Zone struct {
	Zone    string
	Records *Records
}
