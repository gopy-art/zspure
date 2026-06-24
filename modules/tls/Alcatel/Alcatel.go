package alcatel

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type AlcatelNetworks struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (a *AlcatelNetworks) SetCategory(category ...string) {
	a.Category = model.Category.Router()
}

func (a *AlcatelNetworks) SetDeviceName(device ...string) {
	a.DeviceName = "Alcatel Router Panel"
}

func (a *AlcatelNetworks) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.common_name": "Alcatel"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "Alcatel"},
	}
}

func (a *AlcatelNetworks) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "alcatel") {
			return true
		}
	}
	return false
}

func (a *AlcatelNetworks) DeviceScan(banner map[string]interface{}) bool {
	return false
}

func (a *AlcatelNetworks) CveScan(els *handler.Elastic) {}

func (a *AlcatelNetworks) PrintInfo() string { return model.Category.Router() + " | Alcatel Router Panel" }

func (a *AlcatelNetworks) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    a.Category,
		DeviceName:  a.DeviceName,
		Version:     a.Version,
		CveList:     a.CveList,
		Sensibility: a.Sensibility,
		CveScore:    a.CveScore,
	}
}