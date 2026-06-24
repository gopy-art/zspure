package motorola

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type MotorolaSystems struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (m *MotorolaSystems) SetCategory(category ...string) {
	m.Category = model.Category.Router()
}

func (m *MotorolaSystems) SetDeviceName(device ...string) {
	m.DeviceName = "Motorola Systems"
}

func (m *MotorolaSystems) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.common_name": "Motorola"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "Motorola"},
	}
}

func (m *MotorolaSystems) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "motorola") {
			return true
		}
	}
	return false
}

func (m *MotorolaSystems) DeviceScan(banner map[string]interface{}) bool {
	return false
}

func (m *MotorolaSystems) CveScan(els *handler.Elastic) {}

func (m *MotorolaSystems) PrintInfo() string { return model.Category.Router() + " | Motorola Systems" }

func (m *MotorolaSystems) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    m.Category,
		DeviceName:  m.DeviceName,
		Version:     m.Version,
		CveList:     m.CveList,
		Sensibility: m.Sensibility,
		CveScore:    m.CveScore,
	}
}