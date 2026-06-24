package wago

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type WAGOIndustrialPanel struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (w *WAGOIndustrialPanel) SetCategory(category ...string) {
	w.Category = model.Category.Industrial()
}

func (w *WAGOIndustrialPanel) SetDeviceName(device ...string) {
	w.DeviceName = "WAGO Industrial Panel"
}

func (w *WAGOIndustrialPanel) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.common_name": "WAGO"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "WAGO"},
	}
}

func (w *WAGOIndustrialPanel) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "wago") {
			return true
		}
	}
	return false
}

func (w *WAGOIndustrialPanel) DeviceScan(banner map[string]interface{}) bool { return false }
func (w *WAGOIndustrialPanel) CveScan(els *handler.Elastic)                  {}
func (w *WAGOIndustrialPanel) PrintInfo() string                             { return model.Category.Industrial() + " | WAGO Industrial Panel" }

func (w *WAGOIndustrialPanel) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    w.Category,
		DeviceName:  w.DeviceName,
		Version:     w.Version,
		CveList:     w.CveList,
		Sensibility: w.Sensibility,
		CveScore:    w.CveScore,
	}
}