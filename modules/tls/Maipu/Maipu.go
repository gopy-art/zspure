package maipu

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type MaipuRouter struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (m *MaipuRouter) SetCategory(category ...string) {
	m.Category = model.Category.Router()
}

func (m *MaipuRouter) SetDeviceName(device ...string) {
	m.DeviceName = "Maipu Router Panel"
}

func (m *MaipuRouter) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.common_name": "Maipu"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "Maipu"},
	}
}

func (m *MaipuRouter) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "maipu") {
			return true
		}
	}
	return false
}

func (m *MaipuRouter) DeviceScan(banner map[string]interface{}) bool {
	return false
}

func (m *MaipuRouter) CveScan(els *handler.Elastic) {}

func (m *MaipuRouter) PrintInfo() string { return model.Category.Router() + " | Maipu Router Panel" }

func (m *MaipuRouter) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    m.Category,
		DeviceName:  m.DeviceName,
		Version:     m.Version,
		CveList:     m.CveList,
		Sensibility: m.Sensibility,
		CveScore:    m.CveScore,
	}
}