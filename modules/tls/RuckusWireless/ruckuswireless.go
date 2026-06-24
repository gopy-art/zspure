package ruckuswireless

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type RuckusWireless struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (r *RuckusWireless) SetCategory(category ...string) {
	r.Category = model.Category.Router()
}

func (r *RuckusWireless) SetDeviceName(device ...string) {
	r.DeviceName = "Ruckus Wireless"
}

func (r *RuckusWireless) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.common_name": "Ruckus Wireless"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "Ruckus Wireless"},
	}
}

func (r *RuckusWireless) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "ruckus wireless") {
			return true
		}
	}
	return false
}

func (r *RuckusWireless) DeviceScan(banner map[string]interface{}) bool { return false }
func (r *RuckusWireless) CveScan(els *handler.Elastic)                  {}
func (r *RuckusWireless) PrintInfo() string                             { return model.Category.Router() + " | Ruckus Wireless" }

func (r *RuckusWireless) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    r.Category,
		DeviceName:  r.DeviceName,
		Version:     r.Version,
		CveList:     r.CveList,
		Sensibility: r.Sensibility,
		CveScore:    r.CveScore,
	}
}
