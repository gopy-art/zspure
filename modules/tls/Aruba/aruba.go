package aruba

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type ArubaNetworks struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (a *ArubaNetworks) SetCategory(category ...string) {
	a.Category = model.Category.Firewall()
}

func (a *ArubaNetworks) SetDeviceName(device ...string) {
	a.DeviceName = "Aruba Networks"
}

func (a *ArubaNetworks) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.common_name": "Aruba"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "Aruba"},
	}
}

func (a *ArubaNetworks) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "aruba") {
			return true
		}
	}
	return false
}

func (a *ArubaNetworks) DeviceScan(banner map[string]interface{}) bool {
	return false
}

func (a *ArubaNetworks) CveScan(els *handler.Elastic) {}

func (a *ArubaNetworks) PrintInfo() string { return model.Category.Firewall() + " | Aruba Networks" }

func (a *ArubaNetworks) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    a.Category,
		DeviceName:  a.DeviceName,
		Version:     a.Version,
		CveList:     a.CveList,
		Sensibility: a.Sensibility,
		CveScore:    a.CveScore,
	}
}