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

type Record[T any] struct {
	Default *T            `yaml:"default"`
	Regions map[string]*T `yaml:"regions"`
}

type Records struct {
	SOA *record.SOA `yaml:"SOA"`

	A      map[string]*Record[record.A]      `yaml:"A"`
	AAAA   map[string]*Record[record.AAAA]   `yaml:"AAAA"`
	TXT    map[string]*Record[record.TXT]    `yaml:"TXT"`
	CNAME  map[string]*Record[record.CNAME]  `yaml:"CNAME"`
	MX     map[string]*Record[record.MX]     `yaml:"MX"`
	NS     map[string]*Record[record.NS]     `yaml:"NS"`
	PTR    map[string]*Record[record.PTR]    `yaml:"PTR"`
	SRV    map[string]*Record[record.SRV]    `yaml:"SRV"`
	CAA    map[string]*Record[record.CAA]    `yaml:"CAA"`
	CERT   map[string]*Record[record.CERT]   `yaml:"CERT"`
	DNSKEY map[string]*Record[record.DNSKEY] `yaml:"DNSKEY"`
	DS     map[string]*Record[record.DS]     `yaml:"DS"`
	HTTPS  map[string]*Record[record.HTTPS]  `yaml:"HTTPS"`
	LOC    map[string]*Record[record.LOC]    `yaml:"LOC"`
	NAPTR  map[string]*Record[record.NAPTR]  `yaml:"NAPTR"`
	SMIMEA map[string]*Record[record.SMIMEA] `yaml:"SMIMEA"`
	SSHFP  map[string]*Record[record.SSHFP]  `yaml:"SSHFP"`
	SVCB   map[string]*Record[record.SVCB]   `yaml:"SVCB"`
	TLSA   map[string]*Record[record.TLSA]   `yaml:"TLSA"`
	URI    map[string]*Record[record.URI]    `yaml:"URI"`
}

type Zone struct {
	Zone    string   `yaml:"zone"`
	Records *Records `yaml:"records"`
}
