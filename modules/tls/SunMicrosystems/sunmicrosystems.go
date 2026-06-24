package sunmicrosystems

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type SunMicrosystems struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
}

func (s *SunMicrosystems) SetCategory(category ...string) {
	s.Category = model.Category.Server()
}

func (s *SunMicrosystems) SetDeviceName(device ...string) {
	s.DeviceName = "Sun Microsystems"
}

func (s *SunMicrosystems) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.issuer_dn": "Sun Microsystems"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "Sun Microsystems"},
	}
}

func (s *SunMicrosystems) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "sun microsystems") {
			return true
		}
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["issuer_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "sun microsystems") {
			return true
		}
	}
	return false
}

func (s *SunMicrosystems) DeviceScan(banner map[string]interface{}) bool { return false }
func (s *SunMicrosystems) CveScan(els *handler.Elastic)                  {}
func (s *SunMicrosystems) PrintInfo() string                             { return model.Category.Server() + " | Sun Microsystems" }

func (s *SunMicrosystems) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         s.Category,
		DeviceName:       s.DeviceName,
		Version:          s.Version,
		CveList:          s.CveList,
		Sensibility:      s.Sensibility,
		CveScore:         s.CveScore,
	}
}
