package trane

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type Trane struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (t *Trane) SetCategory(category ...string) {
	t.Category = model.Category.Industrial()
}

func (t *Trane) SetDeviceName(device ...string) {
	t.DeviceName = "Trane TLS Panel"
}

func (t *Trane) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.common_name": "Trane"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "Trane"},
	}
}

func (t *Trane) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "trane") {
			return true
		}
	}
	return false
}

func (t *Trane) DeviceScan(banner map[string]interface{}) bool {
	return false
}

func (t *Trane) CveScan(els *handler.Elastic) {}

func (t *Trane) PrintInfo() string { return model.Category.Industrial() + " | Trane TLS Panel" }

func (t *Trane) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    t.Category,
		DeviceName:  t.DeviceName,
		Version:     t.Version,
		CveList:     t.CveList,
		Sensibility: t.Sensibility,
		CveScore:    t.CveScore,
	}
}