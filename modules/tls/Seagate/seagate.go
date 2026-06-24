package seagate

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type SeagateNAS struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (s *SeagateNAS) SetCategory(category ...string) {
	s.Category = model.Category.NetworkStorage()
}

func (s *SeagateNAS) SetDeviceName(device ...string) {
	s.DeviceName = "Seagate NAS"
}

func (s *SeagateNAS) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.common_name": "Seagate"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "Seagate"},
	}
}

func (s *SeagateNAS) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "seagate") {
			return true
		}
	}
	return false
}

func (s *SeagateNAS) DeviceScan(banner map[string]interface{}) bool { return false }
func (s *SeagateNAS) CveScan(els *handler.Elastic)                  {}
func (s *SeagateNAS) PrintInfo() string                             { return model.Category.NetworkStorage() + " | Seagate NAS" }

func (s *SeagateNAS) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    s.Category,
		DeviceName:  s.DeviceName,
		Version:     s.Version,
		CveList:     s.CveList,
		Sensibility: s.Sensibility,
		CveScore:    s.CveScore,
	}
}