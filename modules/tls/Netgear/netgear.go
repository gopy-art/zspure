package netgear

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type NetgearPanel struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (n *NetgearPanel) SetCategory(category ...string) {
	n.Category = model.Category.Router()
}

func (n *NetgearPanel) SetDeviceName(device ...string) {
	n.DeviceName = "Netgear TLS Panel"
}

func (n *NetgearPanel) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.common_name": "netgear"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "netgear"},
	}
}

func (n *NetgearPanel) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "netgear") {
			return true
		}
	}
	return false
}

func (n *NetgearPanel) DeviceScan(banner map[string]interface{}) bool { return false }
func (n *NetgearPanel) CveScan(els *handler.Elastic)                  {}
func (n *NetgearPanel) PrintInfo() string                             { return model.Category.Router() + " | Netgear TLS Panel" }

func (n *NetgearPanel) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    n.Category,
		DeviceName:  n.DeviceName,
		Version:     n.Version,
		CveList:     n.CveList,
		Sensibility: n.Sensibility,
		CveScore:    n.CveScore,
	}
}
