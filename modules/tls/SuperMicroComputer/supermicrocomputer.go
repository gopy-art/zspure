package supermicrocomputer

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type SuperMicroComputer struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (s *SuperMicroComputer) SetCategory(category ...string) {
	s.Category = model.Category.Server()
}

func (s *SuperMicroComputer) SetDeviceName(device ...string) {
	s.DeviceName = "Super Micro Computer"
}

func (s *SuperMicroComputer) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.issuer_dn": "Super Micro Computer"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "Super Micro Computer"},
	}
}

func (s *SuperMicroComputer) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "super micro computer") {
			return true
		}
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["issuer_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "super micro computer") {
			return true
		}
	}
	return false
}

func (s *SuperMicroComputer) DeviceScan(banner map[string]interface{}) bool {
	s.ExtraInformation.NewExtraInfo()
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "ipmi") {
			s.ExtraInformation.SetExtraInfo("product", "IPMI")
		}
	}
	return false
}

func (s *SuperMicroComputer) CveScan(els *handler.Elastic) {}
func (s *SuperMicroComputer) PrintInfo() string {
	return model.Category.Server() + " | Super Micro Computer"
}

func (s *SuperMicroComputer) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         s.Category,
		DeviceName:       s.DeviceName,
		Version:          s.Version,
		CveList:          s.CveList,
		Sensibility:      s.Sensibility,
		CveScore:         s.CveScore,
		ExtraInformation: s.ExtraInformation,
	}
}
