package dns

import "dnsrv/dns/record"

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

type Entry interface {
	Encode() []*record.Answer
}

type Records struct {
	SOA *record.SOA `yaml:"SOA"`

	A map[string]struct {
		Default *record.A            `yaml:"default"`
		Regions map[string]*record.A `yaml:"regions"`
	} `yaml:"A"`

	AAAA map[string]struct {
		Default *record.AAAA            `yaml:"default"`
		Regions map[string]*record.AAAA `yaml:"regions"`
	} `yaml:"AAAA"`

	TXT map[string]struct {
		Default *record.TXT            `yaml:"default"`
		Regions map[string]*record.TXT `yaml:"regions"`
	} `yaml:"TXT"`

	CNAME map[string]struct {
		Default *record.CNAME            `yaml:"default"`
		Regions map[string]*record.CNAME `yaml:"regions"`
	} `yaml:"CNAME"`

	MX map[string]struct {
		Default *record.MX            `yaml:"default"`
		Regions map[string]*record.MX `yaml:"regions"`
	} `yaml:"MX"`

	NS map[string]struct {
		Default *record.NS            `yaml:"default"`
		Regions map[string]*record.NS `yaml:"regions"`
	} `yaml:"NS"`

	PTR map[string]struct {
		Default *record.PTR            `yaml:"default"`
		Regions map[string]*record.PTR `yaml:"regions"`
	} `yaml:"PTR"`

	SRV map[string]struct {
		Default *record.SRV            `yaml:"default"`
		Regions map[string]*record.SRV `yaml:"regions"`
	} `yaml:"SRV"`
}

type Zone struct {
	Zone    string   `yaml:"zone"`
	Records *Records `yaml:"records"`
}
