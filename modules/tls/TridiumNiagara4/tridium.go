package tridiumniagara4

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type TridiumNiagara4 struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (t *TridiumNiagara4) SetCategory(category ...string) {
	t.Category = model.Category.Industrial()
}

func (t *TridiumNiagara4) SetDeviceName(device ...string) {
	t.DeviceName = "Tridium Niagara4 TLS Panel"
}

func (t *TridiumNiagara4) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.common_name": "Tridium"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "Tridium"},
	}
}

func (t *TridiumNiagara4) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "tridium") {
			return true
		}
	}
	return false
}

func (t *TridiumNiagara4) DeviceScan(banner map[string]interface{}) bool {
	return false
}

func (t *TridiumNiagara4) CveScan(els *handler.Elastic) {}

func (t *TridiumNiagara4) PrintInfo() string { return model.Category.Industrial() + " | Tridium Niagara4 TLS Panel" }

func (t *TridiumNiagara4) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    t.Category,
		DeviceName:  t.DeviceName,
		Version:     t.Version,
		CveList:     t.CveList,
		Sensibility: t.Sensibility,
		CveScore:    t.CveScore,
	}
}