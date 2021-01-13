package check

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"text/template"

	"github.com/jreisinger/checkip/util"
)

// ThreatCrowd holds information about an IP address from
// https://www.threatcrowd.org voting.
type ThreatCrowd struct {
	ResponseCode string `json:"response_code"`
	Resolutions  []struct {
		LastResolved string `json:"last_resolved"`
		Domain       string `json:"domain"`
	} `json:"resolutions"`
	Hashes     []string      `json:"hashes"`
	References []interface{} `json:"references"`
	Votes      int           `json:"votes"`
	Permalink  string        `json:"permalink"`
}

// Do retrieves information about the IP address from the ThreatCrowd API. If
// the IP address is voted malicious it returns false.
func (t *ThreatCrowd) Do(ipaddr net.IP) (bool, error) {
	// curl https://www.threatcrowd.org/searchApi/v2/ip/report/?ip=188.40.75.132

	baseURL, err := url.Parse("https://www.threatcrowd.org/searchApi/v2/ip/report")
	if err != nil {
		return false, err
	}

	params := url.Values{}
	params.Add("ip", ipaddr.String())
	baseURL.RawQuery = params.Encode()

	req, err := http.NewRequest("GET", baseURL.String(), nil)
	if err != nil {
		return false, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("search threatcrowd failed: %s", resp.Status)
	}

	if err := json.NewDecoder(resp.Body).Decode(t); err != nil {
		return false, err
	}

	// https://github.com/AlienVault-OTX/ApiV2#votes
	if t.Votes < 0 {
		return false, nil
	}

	return true, nil
}

// Name returns the name of the check.
func (t *ThreatCrowd) Name() string {
	return fmt.Sprint("threatcrowd.org crawlers")
}

// String returns the result of the check.
func (t *ThreatCrowd) String() string {
	funcMap := template.FuncMap{
		"meaning": getVotesMeaning,
	}
	tmpl := `
	votes from AlienVault OTX: {{ .Votes | meaning }}`

	return util.TemplateToString(tmpl, funcMap, t)
}

func getVotesMeaning(n int) string {
	// https://github.com/AlienVault-OTX/ApiV2#votes
	votesMeaning := map[int]string{
		-1: "most users have voted this malicious",
		0:  "equal number of users have voted this malicious and not malicious",
		1:  "most users have voted this not malicious",
	}
	return votesMeaning[n]
}
