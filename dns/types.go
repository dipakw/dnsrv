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
}

type Zone struct {
	Zone    string   `yaml:"zone"`
	Records *Records `yaml:"records"`
}
