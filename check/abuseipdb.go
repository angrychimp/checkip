package check

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"github.com/jreisinger/checkip/util"
)

// AbuseIPDB holds information about an IP address from abuseipdb.com database.
type AbuseIPDB struct {
	Data struct {
		AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
		UsageType            string `json:"usageType"`
		Domain               string `json:"domain"`
		TotalReports         int    `json:"totalReports"`
	} `json:"data"`
}

// Do fills in AbuseIPDB data for a given IP address. Its get the data from
// https://api.abuseipdb.com/api/v2/check
// (https://docs.abuseipdb.com/#check-endpoint).
func (a *AbuseIPDB) Do(ipaddr net.IP) (bool, error) {
	apiKey, err := util.GetConfigValue("ABUSEIPDB_API_KEY")
	if err != nil {
		return false, fmt.Errorf("can't call API: %w", err)
	}

	baseURL, err := url.Parse("https://api.abuseipdb.com/api/v2/check")
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

	if a.Data.AbuseConfidenceScore > 25 {
		return false, nil
	}

	return true, nil
}

// Name returns the name of the check.
func (a *AbuseIPDB) Name() string {
	return fmt.Sprint("AbuseIPDB")
}

// String returns the result of the check.
func (a *AbuseIPDB) String() string {
	return fmt.Sprintf("%d reports, %d%% confidence | %s | %s",
		a.Data.TotalReports,
		a.Data.AbuseConfidenceScore,
		a.Data.Domain,
		a.Data.UsageType,
	)
}
