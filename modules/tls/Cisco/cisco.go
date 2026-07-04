package cisco

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type Cisco struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (c *Cisco) SetCategory(category ...string) {
	c.Category = model.Category.Router()
}

func (c *Cisco) SetDeviceName(device ...string) {
	c.DeviceName = "Cisco"
}

func (c *Cisco) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.issuer_dn": "Cisco Appliance"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "Cisco Systems, Inc"},
	}
}

func (c *Cisco) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["issuer_dn"].(string); ok {
		if strings.Contains(strings.ToLower(val), "cisco systems") {
			return true
		}
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"].(string); ok {
		if strings.Contains(strings.ToLower(val), "cisco systems") {
			return true
		}
	}
	return false
}

func (c *Cisco) DeviceScan(banner map[string]interface{}) bool { return false }
func (c *Cisco) CveScan(els *handler.Elastic)                  {}
func (c *Cisco) PrintInfo() string                             { return model.Category.Router() + " | Cisco" }

func (c *Cisco) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    c.Category,
		DeviceName:  c.DeviceName,
		Version:     c.Version,
		CveList:     c.CveList,
		Sensibility: c.Sensibility,
		CveScore:    c.CveScore,
	}
}
