package checkpoint

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type CheckPoint struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (c *CheckPoint) SetCategory(category ...string) {
	c.Category = model.Category.Firewall()
}

func (c *CheckPoint) SetDeviceName(device ...string) {
	c.DeviceName = "Check Point"
}

func (c *CheckPoint) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.organization": "check point"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "checkpoint"},
	}
}

func (c *CheckPoint) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "checkpoint") || strings.Contains(strings.ToLower(val.(string)), "check point") {
			return true
		}
	}
	return false
}

func (c *CheckPoint) DeviceScan(banner map[string]interface{}) bool {
	return false
}

func (c *CheckPoint) CveScan(els *handler.Elastic) {}

func (c *CheckPoint) PrintInfo() string { return model.Category.Firewall() + " | Check Point" }

func (c *CheckPoint) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    c.Category,
		DeviceName:  c.DeviceName,
		Version:     c.Version,
		CveList:     c.CveList,
		Sensibility: c.Sensibility,
		CveScore:    c.CveScore,
	}
}