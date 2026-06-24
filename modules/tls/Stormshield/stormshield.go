package stormshield

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type Stormshield struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (s *Stormshield) SetCategory(category ...string) {
	s.Category = model.Category.Firewall()
}

func (s *Stormshield) SetDeviceName(device ...string) {
	s.DeviceName = "Stormshield"
}

func (s *Stormshield) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.common_name": "Stormshield"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "Stormshield"},
	}
}

func (s *Stormshield) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "stormshield") {
			return true
		}
	}
	return false
}

func (s *Stormshield) DeviceScan(banner map[string]interface{}) bool { return false }
func (s *Stormshield) CveScan(els *handler.Elastic)                  {}
func (s *Stormshield) PrintInfo() string                             { return model.Category.Firewall() + " | Stormshield" }

func (s *Stormshield) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    s.Category,
		DeviceName:  s.DeviceName,
		Version:     s.Version,
		CveList:     s.CveList,
		Sensibility: s.Sensibility,
		CveScore:    s.CveScore,
	}
}