package tplink

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type TPLink struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (t *TPLink) SetCategory(category ...string) {
	t.Category = model.Category.Router()
}

func (t *TPLink) SetDeviceName(device ...string) {
	t.DeviceName = "TP-Link TLS Panel"
}

func (t *TPLink) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.common_name": "TP-LINK"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "TP-LINK"},
	}
}

func (t *TPLink) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "tp-link") {
			return true
		}
	}
	return false
}

func (t *TPLink) DeviceScan(banner map[string]interface{}) bool {
	return false
}

func (t *TPLink) CveScan(els *handler.Elastic) {}

func (t *TPLink) PrintInfo() string { return model.Category.Router() + " | TP-Link TLS Panel" }

func (t *TPLink) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    t.Category,
		DeviceName:  t.DeviceName,
		Version:     t.Version,
		CveList:     t.CveList,
		Sensibility: t.Sensibility,
		CveScore:    t.CveScore,
	}
}