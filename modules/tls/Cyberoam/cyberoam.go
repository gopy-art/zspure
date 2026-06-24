package cyberoam

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type Cyberoam struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (c *Cyberoam) SetCategory(category ...string) {
	c.Category = model.Category.Firewall()
}

func (c *Cyberoam) SetDeviceName(device ...string) {
	c.DeviceName = "Cyberoam"
}

func (c *Cyberoam) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.common_name": "Cyberoam"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "Cyberoam"},
	}
}

func (c *Cyberoam) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "cyberoam") {
			return true
		}
	}
	return false
}

func (c *Cyberoam) DeviceScan(banner map[string]interface{}) bool { return false }
func (c *Cyberoam) CveScan(els *handler.Elastic)                  {}
func (c *Cyberoam) PrintInfo() string                             { return model.Category.Firewall() + " | Cyberoam" }

func (c *Cyberoam) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    c.Category,
		DeviceName:  c.DeviceName,
		Version:     c.Version,
		CveList:     c.CveList,
		Sensibility: c.Sensibility,
		CveScore:    c.CveScore,
	}
}
