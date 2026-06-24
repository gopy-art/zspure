package schneider

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type SchneiderEcostruxure struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (s *SchneiderEcostruxure) SetCategory(category ...string) {
	s.Category = model.Category.Industrial()
}

func (s *SchneiderEcostruxure) SetDeviceName(device ...string) {
	s.DeviceName = "Schneider Ecostruxure TLS Panel"
}

func (s *SchneiderEcostruxure) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.common_name": "Schneider"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "Schneider"},
	}
}

func (s *SchneiderEcostruxure) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "schneider") {
			return true
		}
	}
	return false
}

func (s *SchneiderEcostruxure) DeviceScan(banner map[string]interface{}) bool {
	return false
}

func (s *SchneiderEcostruxure) CveScan(els *handler.Elastic) {}

func (s *SchneiderEcostruxure) PrintInfo() string { return model.Category.Industrial() + " | Schneider Ecostruxure TLS Panel" }

func (s *SchneiderEcostruxure) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    s.Category,
		DeviceName:  s.DeviceName,
		Version:     s.Version,
		CveList:     s.CveList,
		Sensibility: s.Sensibility,
		CveScore:    s.CveScore,
	}
}