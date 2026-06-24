package siemens

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type SiemensSystems struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (s *SiemensSystems) SetCategory(category ...string) {
	s.Category = model.Category.Industrial()
}

func (s *SiemensSystems) SetDeviceName(device ...string) {
	s.DeviceName = "Siemens Systems Panel"
}

func (s *SiemensSystems) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.common_name": "Siemens"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "Siemens"},
	}
}

func (s *SiemensSystems) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "siemens") {
			return true
		}
	}
	return false
}

func (s *SiemensSystems) DeviceScan(banner map[string]interface{}) bool { return false }
func (s *SiemensSystems) CveScan(els *handler.Elastic)                  {}
func (s *SiemensSystems) PrintInfo() string                             { return model.Category.Industrial() + " | Siemens Systems Panel" }

func (s *SiemensSystems) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    s.Category,
		DeviceName:  s.DeviceName,
		Version:     s.Version,
		CveList:     s.CveList,
		Sensibility: s.Sensibility,
		CveScore:    s.CveScore,
	}
}
