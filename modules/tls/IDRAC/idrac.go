package idrac

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type IDRACServer struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (i *IDRACServer) SetCategory(category ...string) {
	i.Category = model.Category.Server()
}

func (i *IDRACServer) SetDeviceName(device ...string) {
	i.DeviceName = "IDRAC (Remote Access Controller)"
}

func (i *IDRACServer) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.common_name": "Idrac"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "Idrac"},
	}
}

func (i *IDRACServer) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "idrac") {
			return true
		}
	}
	return false
}

func (i *IDRACServer) DeviceScan(banner map[string]interface{}) bool { return false }
func (i *IDRACServer) CveScan(els *handler.Elastic) {}
func (i *IDRACServer) PrintInfo() string { return model.Category.Server() + " | IDRAC (Remote Access Controller)" }

func (i *IDRACServer) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    i.Category,
		DeviceName:  i.DeviceName,
		Version:     i.Version,
		CveList:     i.CveList,
		Sensibility: i.Sensibility,
		CveScore:    i.CveScore,
	}
}