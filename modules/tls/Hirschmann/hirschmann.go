package hirschmann

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type Hirschmann struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (h *Hirschmann) SetCategory(category ...string) {
	h.Category = model.Category.Firewall()
}

func (h *Hirschmann) SetDeviceName(device ...string) {
	h.DeviceName = "Hirschmann Eagle"
}

func (h *Hirschmann) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.issuer.organizational_unit": "Hirschmann Automation and Control"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "Hirschmann Automation and Control"},
	}
}

func (h *Hirschmann) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), strings.ToLower("Hirschmann Automation and Control")) {
			return true
		}
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["issuer_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), strings.ToLower("Hirschmann Automation and Control")) {
			return true
		}
	}
	return false
}

func (h *Hirschmann) DeviceScan(banner map[string]interface{}) bool { return false }
func (h *Hirschmann) CveScan(els *handler.Elastic)                  {}
func (h *Hirschmann) PrintInfo() string                             { return model.Category.Firewall() + " | Hirschmann Eagle" }

func (h *Hirschmann) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    h.Category,
		DeviceName:  h.DeviceName,
		Version:     h.Version,
		CveList:     h.CveList,
		Sensibility: h.Sensibility,
		CveScore:    h.CveScore,
	}
}
