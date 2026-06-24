package endresshauser

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type EndressHauser struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (e *EndressHauser) SetCategory(category ...string) {
	e.Category = model.Category.Industrial()
}

func (e *EndressHauser) SetDeviceName(device ...string) {
	e.DeviceName = "Endress+Hauser TLS Panel"
}

func (e *EndressHauser) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.common_name": "hauser"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "hauser"},
	}
}

func (e *EndressHauser) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "hauser") && strings.Contains(strings.ToLower(val.(string)), "endress") {
			return true
		}
	}
	return false
}

func (e *EndressHauser) DeviceScan(banner map[string]interface{}) bool {
	return false
}

func (e *EndressHauser) CveScan(els *handler.Elastic) {}

func (e *EndressHauser) PrintInfo() string { return model.Category.Industrial() + " | Endress+Hauser TLS Panel" }

func (e *EndressHauser) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    e.Category,
		DeviceName:  e.DeviceName,
		Version:     e.Version,
		CveList:     e.CveList,
		Sensibility: e.Sensibility,
		CveScore:    e.CveScore,
	}
}