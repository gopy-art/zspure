package westermo

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type WestermoTeleindustrial struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (w *WestermoTeleindustrial) SetCategory(category ...string) {
	w.Category = model.Category.Firewall()
}

func (w *WestermoTeleindustrial) SetDeviceName(device ...string) {
	w.DeviceName = "Westermo Teleindustrial"
}

func (w *WestermoTeleindustrial) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.common_name": "Westermo"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "Westermo"},
	}
}

func (w *WestermoTeleindustrial) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "westermo") {
			return true
		}
	}
	return false
}

func (w *WestermoTeleindustrial) DeviceScan(banner map[string]interface{}) bool { return false }
func (w *WestermoTeleindustrial) CveScan(els *handler.Elastic)                  {}
func (w *WestermoTeleindustrial) PrintInfo() string                             { return model.Category.Firewall() + " | Westermo Teleindustrial" }

func (w *WestermoTeleindustrial) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    w.Category,
		DeviceName:  w.DeviceName,
		Version:     w.Version,
		CveList:     w.CveList,
		Sensibility: w.Sensibility,
		CveScore:    w.CveScore,
	}
}
