package draytek

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type DrayTek struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (d *DrayTek) SetCategory(category ...string) {
	d.Category = model.Category.Router()
}

func (d *DrayTek) SetDeviceName(device ...string) {
	d.DeviceName = "DrayTek Vigor"
}

func (d *DrayTek) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.common_name": "DrayTek"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "DrayTek"},
	}
}

func (d *DrayTek) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "draytek") {
			return true
		}
	}
	return false
}

func (d *DrayTek) DeviceScan(banner map[string]interface{}) bool {
	return false
}

func (d *DrayTek) CveScan(els *handler.Elastic) {}

func (d *DrayTek) PrintInfo() string { return model.Category.Router() + " | DrayTek Vigor" }

func (d *DrayTek) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    d.Category,
		DeviceName:  d.DeviceName,
		Version:     d.Version,
		CveList:     d.CveList,
		Sensibility: d.Sensibility,
		CveScore:    d.CveScore,
	}
}