package hillstone

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type HillstoneNetworks struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (h *HillstoneNetworks) SetCategory(category ...string) {
	h.Category = model.Category.Firewall()
}

func (h *HillstoneNetworks) SetDeviceName(device ...string) {
	h.DeviceName = "Hillstone"
}

func (h *HillstoneNetworks) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.common_name": "Hillstone"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "Hillstone"},
	}
}

func (h *HillstoneNetworks) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "hillstone") {
			return true
		}
	}
	return false
}

func (h *HillstoneNetworks) DeviceScan(banner map[string]interface{}) bool { return false }
func (h *HillstoneNetworks) CveScan(els *handler.Elastic) {}
func (h *HillstoneNetworks) PrintInfo() string { return model.Category.Firewall() + " | Hillstone" }

func (h *HillstoneNetworks) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    h.Category,
		DeviceName:  h.DeviceName,
		Version:     h.Version,
		CveList:     h.CveList,
		Sensibility: h.Sensibility,
		CveScore:    h.CveScore,
	}
}