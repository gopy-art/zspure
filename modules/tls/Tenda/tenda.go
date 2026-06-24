package tenda

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type TendaRouter struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (t *TendaRouter) SetCategory(category ...string) {
	t.Category = model.Category.Router()
}

func (t *TendaRouter) SetDeviceName(device ...string) {
	t.DeviceName = "Tenda Router Panel"
}

func (t *TendaRouter) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.common_name": "Tenda"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "Tenda"},
	}
}

func (t *TendaRouter) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "tenda") {
			return true
		}
	}
	return false
}

func (t *TendaRouter) DeviceScan(banner map[string]interface{}) bool {
	return false
}

func (t *TendaRouter) CveScan(els *handler.Elastic) {}

func (t *TendaRouter) PrintInfo() string { return model.Category.Router() + " | Tenda Router Panel" }

func (t *TendaRouter) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    t.Category,
		DeviceName:  t.DeviceName,
		Version:     t.Version,
		CveList:     t.CveList,
		Sensibility: t.Sensibility,
		CveScore:    t.CveScore,
	}
}