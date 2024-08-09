package dns

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v2"
)

var zones map[string]*Zone = map[string]*Zone{
	// ...
}

func (c *Config) Load() {
	c.loadZones()
}

func (c *Config) loadZones() error {

	for _, dir := range c.Zones {

		files, err := os.ReadDir(dir)

		if err != nil {
			return err
		}

		for _, f := range files {
			file, err := os.ReadFile(filepath.Join(dir, f.Name()))

			if err != nil {
				return err
			}

			zone := Zone{}

			err = yaml.Unmarshal(file, &zone)

			if err != nil {
				return err
			}

			zones[zone.Zone] = &zone
		}

	}

	return nil

}
