package synology

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type SynologyNAS struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (s *SynologyNAS) SetCategory(category ...string) {
	s.Category = model.Category.NetworkStorage()
}

func (s *SynologyNAS) SetDeviceName(device ...string) {
	s.DeviceName = "Synology NAS"
}

func (s *SynologyNAS) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.common_name": "Synology"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "Synology"},
	}
}

func (s *SynologyNAS) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "synology") {
			return true
		}
	}
	return false
}

func (s *SynologyNAS) DeviceScan(banner map[string]interface{}) bool { return false }
func (s *SynologyNAS) CveScan(els *handler.Elastic)                  {}
func (s *SynologyNAS) PrintInfo() string                             { return model.Category.NetworkStorage() + " | Synology NAS" }

func (s *SynologyNAS) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    s.Category,
		DeviceName:  s.DeviceName,
		Version:     s.Version,
		CveList:     s.CveList,
		Sensibility: s.Sensibility,
		CveScore:    s.CveScore,
	}
}