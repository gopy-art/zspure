package topsec

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type Topsec struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (t *Topsec) SetCategory(category ...string) {
	t.Category = model.Category.Firewall()
}

func (t *Topsec) SetDeviceName(device ...string) {
	t.DeviceName = "Topsec"
}

func (t *Topsec) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.common_name": "topsec"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "topsec"},
	}
}

func (t *Topsec) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "topsec") {
			return true
		}
	}
	return false
}

func (t *Topsec) DeviceScan(banner map[string]interface{}) bool {
	return false
}

func (t *Topsec) CveScan(els *handler.Elastic) {}

func (t *Topsec) PrintInfo() string { return model.Category.Firewall() + " | Topsec" }

func (t *Topsec) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    t.Category,
		DeviceName:  t.DeviceName,
		Version:     t.Version,
		CveList:     t.CveList,
		Sensibility: t.Sensibility,
		CveScore:    t.CveScore,
	}
}