package openwrt

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type OpenwrtRouter struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (o *OpenwrtRouter) SetCategory(category ...string) {
	o.Category = model.Category.Router()
}

func (o *OpenwrtRouter) SetDeviceName(device ...string) {
	o.DeviceName = "Openwrt TLS Panel"
}

func (o *OpenwrtRouter) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.common_name": "Openwrt"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "Openwrt"},
	}
}

func (o *OpenwrtRouter) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "openwrt") {
			return true
		}
	}
	return false
}

func (o *OpenwrtRouter) DeviceScan(banner map[string]interface{}) bool { return false }
func (o *OpenwrtRouter) CveScan(els *handler.Elastic)                  {}
func (o *OpenwrtRouter) PrintInfo() string                             { return model.Category.Router() + " | Openwrt TLS Panel" }

func (o *OpenwrtRouter) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    o.Category,
		DeviceName:  o.DeviceName,
		Version:     o.Version,
		CveList:     o.CveList,
		Sensibility: o.Sensibility,
		CveScore:    o.CveScore,
	}
}
