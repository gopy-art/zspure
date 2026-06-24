package mitsubishi

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type Mitsubishi struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (m *Mitsubishi) SetCategory(category ...string) {
	m.Category = model.Category.Industrial()
}

func (m *Mitsubishi) SetDeviceName(device ...string) {
	m.DeviceName = "Mitsubishi TLS Panel"
}

func (m *Mitsubishi) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.common_name": "Mitsubishi"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "Mitsubishi"},
	}
}

func (m *Mitsubishi) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "mitsubishi") {
			return true
		}
	}
	return false
}

func (m *Mitsubishi) DeviceScan(banner map[string]interface{}) bool {
	return false
}

func (m *Mitsubishi) CveScan(els *handler.Elastic) {}

func (m *Mitsubishi) PrintInfo() string { return model.Category.Industrial() + " | Mitsubishi TLS Panel" }

func (m *Mitsubishi) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    m.Category,
		DeviceName:  m.DeviceName,
		Version:     m.Version,
		CveList:     m.CveList,
		Sensibility: m.Sensibility,
		CveScore:    m.CveScore,
	}
}