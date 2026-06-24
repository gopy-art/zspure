package asusrouter

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type AsusRouter struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (a *AsusRouter) SetCategory(category ...string) {
	a.Category = model.Category.Router()
}

func (a *AsusRouter) SetDeviceName(device ...string) {
	a.DeviceName = "Asus Router"
}

func (a *AsusRouter) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.common_name": "Asus"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "Router"},
	}
}

func (a *AsusRouter) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "router") && strings.Contains(strings.ToLower(val.(string)), "asus") {
			return true
		}
	}
	return false
}

func (a *AsusRouter) DeviceScan(banner map[string]interface{}) bool {
	return false
}

func (a *AsusRouter) CveScan(els *handler.Elastic) {}

func (a *AsusRouter) PrintInfo() string { return model.Category.Router() + " | Asus Router" }

func (a *AsusRouter) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    a.Category,
		DeviceName:  a.DeviceName,
		Version:     a.Version,
		CveList:     a.CveList,
		Sensibility: a.Sensibility,
		CveScore:    a.CveScore,
	}
}