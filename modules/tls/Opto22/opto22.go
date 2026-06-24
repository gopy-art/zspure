package opto22

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type Opto22 struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (o *Opto22) SetCategory(category ...string) {
	o.Category = model.Category.Industrial()
}

func (o *Opto22) SetDeviceName(device ...string) {
	o.DeviceName = "Opto-22 TLS Panel"
}

func (o *Opto22) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.common_name": "opto"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "opto"},
	}
}

func (o *Opto22) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "opto") {
			return true
		}
	}
	return false
}

func (o *Opto22) DeviceScan(banner map[string]interface{}) bool {
	return false
}

func (o *Opto22) CveScan(els *handler.Elastic) {}

func (o *Opto22) PrintInfo() string { return model.Category.Industrial() + " | Opto-22 TLS Panel" }

func (o *Opto22) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    o.Category,
		DeviceName:  o.DeviceName,
		Version:     o.Version,
		CveList:     o.CveList,
		Sensibility: o.Sensibility,
		CveScore:    o.CveScore,
	}
}