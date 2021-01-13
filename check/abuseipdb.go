package check

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"text/template"
	"time"

	"github.com/jreisinger/checkip/util"
)

// AbuseIPDB holds information about an IP address from abuseipdb.com database.
type AbuseIPDB struct {
	Data struct {
		IsWhitelisted        bool      `json:"isWhitelisted"`
		AbuseConfidenceScore int       `json:"abuseConfidenceScore"`
		UsageType            string    `json:"usageType"`
		Domain               string    `json:"domain"`
		TotalReports         int       `json:"totalReports"`
		LastReportedAt       time.Time `json:"lastReportedAt"`
		// IPAddress            string        `json:"ipAddress"`
		// IsPublic             bool          `json:"isPublic"`
		// IPVersion            int           `json:"ipVersion"`
		// CountryCode          string        `json:"countryCode"`
		// Isp                  string        `json:"isp"`
		// Hostnames []interface{} `json:"hostnames"`
		// CountryName          string        `json:"countryName"`
		// NumDistinctUsers     int           `json:"numDistinctUsers"`
		// Reports              []struct {
		// 	ReportedAt          time.Time `json:"reportedAt"`
		// 	Comment             string    `json:"comment"`
		// 	Categories          []int     `json:"categories"`
		// 	ReporterID          int       `json:"reporterId"`
		// 	ReporterCountryCode string    `json:"reporterCountryCode"`
		// 	ReporterCountryName string    `json:"reporterCountryName"`
		// } `json:"reports"`
	} `json:"data"`
	Source string
}

// Do fills in AbuseIPDB data for a given IP address. See the AbuseIPDB API
// documentation for more https://docs.abuseipdb.com/?shell#check-endpoint
func (a *AbuseIPDB) Do(ipaddr net.IP) (bool, error) {
	apiKey, err := util.GetConfigValue("ABUSEIPDB_API_KEY")
	if err != nil {
		return false, fmt.Errorf("can't call API: %w", err)
	}

	a.Source = "https://api.abuseipdb.com/api/v2/check"
	baseURL, err := url.Parse(a.Source)
	if err != nil {
		return false, err
	}

	// Add GET paramaters.
	params := url.Values{}
	params.Add("ipAddress", ipaddr.String())
	baseURL.RawQuery = params.Encode()

	req, err := http.NewRequest("GET", baseURL.String(), nil)
	if err != nil {
		return false, err
	}

	// Set request headers.
	req.Header.Set("Key", apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("calling API: %s", resp.Status)
	}

	if err := json.NewDecoder(resp.Body).Decode(a); err != nil {
		return false, err
	}

	if a.Data.AbuseConfidenceScore > 0 && !a.Data.IsWhitelisted {
		return false, nil
	}

	return true, nil
}

// Name returns the name of the check.
func (a *AbuseIPDB) Name() string {
	return fmt.Sprint("abuseipdb.com")
}

// Result returns the result of the check.
func (a *AbuseIPDB) Result(verbose bool) string {
	funcMap := template.FuncMap{}
	const tmpl = `
		whitelisted:   {{.Data.IsWhitelisted}}
		last reported: {{.Data.LastReportedAt}}
		total reports: {{.Data.TotalReports}}
		domain:        {{.Data.Domain}}
		usage:	       {{.Data.UsageType}}
		source:	       {{.Source}}`

	result := fmt.Sprintf("malicious with %d%% confidence", a.Data.AbuseConfidenceScore)
	if verbose {
		result += util.TemplateToString(tmpl, funcMap, a)
	}
	return result
}
