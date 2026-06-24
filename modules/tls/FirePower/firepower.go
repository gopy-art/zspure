package firepower

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type CiscoFirePower struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (c *CiscoFirePower) SetCategory(category ...string) {
	c.Category = model.Category.Firewall()
}

func (c *CiscoFirePower) SetDeviceName(device ...string) {
	c.DeviceName = "Cisco FirePower"
}

func (c *CiscoFirePower) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.common_name": "firepower"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "firepower"},
	}
}

func (c *CiscoFirePower) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "firepower") {
			return true
		}
	}
	return false
}

func (c *CiscoFirePower) DeviceScan(banner map[string]interface{}) bool {
	return false
}

func (c *CiscoFirePower) CveScan(els *handler.Elastic) {}

func (c *CiscoFirePower) PrintInfo() string { return model.Category.Firewall() + " | Cisco FirePower" }

func (c *CiscoFirePower) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    c.Category,
		DeviceName:  c.DeviceName,
		Version:     c.Version,
		CveList:     c.CveList,
		Sensibility: c.Sensibility,
		CveScore:    c.CveScore,
	}
}