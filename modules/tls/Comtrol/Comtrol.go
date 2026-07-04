package comtrol

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type Comtrol struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (c *Comtrol) SetCategory(category ...string) {
	c.Category = model.Category.Industrial()
}

func (c *Comtrol) SetDeviceName(device ...string) {
	c.DeviceName = "Comtrol"
}

func (c *Comtrol) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.issuer_dn": "Comtrol"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "Comtrol"},
	}
}

func (c *Comtrol) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"].(string); ok {
		if strings.Contains(strings.ToLower(val), "comtrol") {
			return true
		}
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["issuer_dn"].(string); ok {
		if strings.Contains(strings.ToLower(val), "comtrol") {
			return true
		}
	}
	return false
}

func (c *Comtrol) DeviceScan(banner map[string]interface{}) bool { return false }
func (c *Comtrol) CveScan(els *handler.Elastic)                  {}
func (c *Comtrol) PrintInfo() string                             { return model.Category.Industrial() + " | Comtrol" }

func (c *Comtrol) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    c.Category,
		DeviceName:  c.DeviceName,
		Version:     c.Version,
		CveList:     c.CveList,
		Sensibility: c.Sensibility,
		CveScore:    c.CveScore,
	}
}
