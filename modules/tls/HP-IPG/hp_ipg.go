package hpipg

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type HPIRGHTTPS struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (h *HPIRGHTTPS) SetCategory(category ...string) {
	h.Category = model.Category.Printer()
}

func (h *HPIRGHTTPS) SetDeviceName(device ...string) {
	h.DeviceName = "HP-IPG"
}

func (h *HPIRGHTTPS) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.issuer.organizational_unit": "HP-IPG"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "HP-IPG"},
	}
}

func (h *HPIRGHTTPS) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "hp-ipg") {
			return true
		}
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["issuer_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "hp-ipg") {
			return true
		}
	}
	return false
}

func (h *HPIRGHTTPS) DeviceScan(banner map[string]interface{}) bool { return false }
func (h *HPIRGHTTPS) CveScan(els *handler.Elastic)                  {}
func (h *HPIRGHTTPS) PrintInfo() string                             { return model.Category.Printer() + " | HP-IPG" }

func (h *HPIRGHTTPS) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    h.Category,
		DeviceName:  h.DeviceName,
		Version:     h.Version,
		CveList:     h.CveList,
		Sensibility: h.Sensibility,
		CveScore:    h.CveScore,
	}
}
