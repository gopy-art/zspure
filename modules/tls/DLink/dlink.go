package dlink

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type DLink struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (d *DLink) SetCategory(category ...string) {
	d.Category = model.Category.Router()
}

func (d *DLink) SetDeviceName(device ...string) {
	d.DeviceName = "D-Link TLS Panel"
}

func (d *DLink) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.common_name": "D-Link"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "D-Link"},
	}
}

func (d *DLink) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "d-link") {
			return true
		}
	}
	return false
}

func (d *DLink) DeviceScan(banner map[string]interface{}) bool {
	return false
}

func (d *DLink) CveScan(els *handler.Elastic) {}

func (d *DLink) PrintInfo() string { return model.Category.Router() + " | D-Link TLS Panel" }

func (d *DLink) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    d.Category,
		DeviceName:  d.DeviceName,
		Version:     d.Version,
		CveList:     d.CveList,
		Sensibility: d.Sensibility,
		CveScore:    d.CveScore,
	}
}