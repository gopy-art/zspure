package westerndigital

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type WesternDigital struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (w *WesternDigital) SetCategory(category ...string) {
	w.Category = model.Category.NetworkStorage()
}

func (w *WesternDigital) SetDeviceName(device ...string) {
	w.DeviceName = "Western Digital"
}

func (w *WesternDigital) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.issuer_dn": "Western Digital"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "Western Digital"},
	}
}

func (w *WesternDigital) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "western digital") {
			return true
		}
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["issuer_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "western digital") {
			return true
		}
	}
	return false
}

func (w *WesternDigital) DeviceScan(banner map[string]interface{}) bool { return false }
func (w *WesternDigital) CveScan(els *handler.Elastic) {}
func (w *WesternDigital) PrintInfo() string {
	return model.Category.NetworkStorage() + " | Western Digital"
}

func (w *WesternDigital) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    w.Category,
		DeviceName:  w.DeviceName,
		Version:     w.Version,
		CveList:     w.CveList,
		Sensibility: w.Sensibility,
		CveScore:    w.CveScore,
	}
}
