package check

import (
	"fmt"
	"net"
	"text/template"

	"github.com/jreisinger/checkip/util"
	"github.com/oschwald/geoip2-golang"
)

// Geo holds geographic location from MaxMind's GeoIP database.
type Geo struct {
	City    string
	Country string
	IsoCode string
	Source  string
}

// Do fills in the geolocation data.
func (g *Geo) Do(ip net.IP) (bool, error) {
	licenseKey, err := util.GetConfigValue("GEOIP_LICENSE_KEY")
	if err != nil {
		return false, fmt.Errorf("getting licence key: %w", err)
	}

	file := "/var/tmp/GeoLite2-City.mmdb"
	g.Source = "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City"
	url := g.Source + "&license_key=" + licenseKey + "&suffix=tar.gz"

	if err := util.Update(file, url, "tgz"); err != nil {
		return false, fmt.Errorf("can't update DB file: %v", err)
	}

	db, err := geoip2.Open(file)
	if err != nil {
		return false, fmt.Errorf("can't load DB file: %v", err)
	}
	defer db.Close()

	record, err := db.City(ip)
	if err != nil {
		return false, err
	}

	g.City = record.City.Names["en"]
	g.Country = record.Country.Names["en"]
	g.IsoCode = record.Country.IsoCode

	return true, nil
}

// Name returns the name of the check.
func (g *Geo) Name() string {
	return fmt.Sprint("GEO")
}

// Result returns the result of the check.
func (g *Geo) Result(verbose bool) string {

	funcMap := template.FuncMap{}
	const tmpl = `
		City:     {{.City}}
		ISO code: {{.IsoCode}}
		Source:   {{.Source}}`
	result := fmt.Sprintf("%s", g.Country)
	if verbose {
		result += util.TemplateToString(tmpl, funcMap, g)
	}
	return result
}
