package deosag

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type DEOSAG struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (d *DEOSAG) SetCategory(category ...string) {
	d.Category = model.Category.Industrial()
}

func (d *DEOSAG) SetDeviceName(device ...string) {
	d.DeviceName = "DEOS AG TLS Panel"
}

func (d *DEOSAG) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.common_name": "DEOS AG"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "DEOS AG"},
	}
}

func (d *DEOSAG) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "deos ag") {
			return true
		}
	}
	return false
}

func (d *DEOSAG) DeviceScan(banner map[string]interface{}) bool {
	return false
}

func (d *DEOSAG) CveScan(els *handler.Elastic) {}

func (d *DEOSAG) PrintInfo() string { return model.Category.Industrial() + " | DEOS AG TLS Panel" }

func (d *DEOSAG) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    d.Category,
		DeviceName:  d.DeviceName,
		Version:     d.Version,
		CveList:     d.CveList,
		Sensibility: d.Sensibility,
		CveScore:    d.CveScore,
	}
}