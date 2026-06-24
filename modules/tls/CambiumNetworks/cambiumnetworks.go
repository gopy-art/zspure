package cambiumnetworks

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type CambiumNetworks struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (c *CambiumNetworks) SetCategory(category ...string) {
	c.Category = model.Category.Router()
}

func (c *CambiumNetworks) SetDeviceName(device ...string) {
	c.DeviceName = "Cambium Networks R195W"
}

func (c *CambiumNetworks) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.common_name": "voip"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "voip"},
	}
}

func (c *CambiumNetworks) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "voip") {
			return true
		}
	}
	return false
}

func (c *CambiumNetworks) DeviceScan(banner map[string]interface{}) bool { return false }
func (c *CambiumNetworks) CveScan(els *handler.Elastic)                  {}
func (c *CambiumNetworks) PrintInfo() string                             { return model.Category.Router() + " | Cambium Networks R195W" }

func (c *CambiumNetworks) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    c.Category,
		DeviceName:  c.DeviceName,
		Version:     c.Version,
		CveList:     c.CveList,
		Sensibility: c.Sensibility,
		CveScore:    c.CveScore,
	}
}
