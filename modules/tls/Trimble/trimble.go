package trimble

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type Trimble struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (t *Trimble) SetCategory(category ...string) {
	t.Category = model.Category.Industrial()
}

func (t *Trimble) SetDeviceName(device ...string) {
	t.DeviceName = "Trimble TLS Panel"
}

func (t *Trimble) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.common_name": "Trimble"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "Trimble"},
	}
}

func (t *Trimble) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "trimble") {
			return true
		}
	}
	return false
}

func (t *Trimble) DeviceScan(banner map[string]interface{}) bool {
	return false
}

func (t *Trimble) CveScan(els *handler.Elastic) {}

func (t *Trimble) PrintInfo() string { return model.Category.Industrial() + " | Trimble TLS Panel" }

func (t *Trimble) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    t.Category,
		DeviceName:  t.DeviceName,
		Version:     t.Version,
		CveList:     t.CveList,
		Sensibility: t.Sensibility,
		CveScore:    t.CveScore,
	}
}