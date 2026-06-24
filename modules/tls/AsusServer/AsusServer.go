package asusserver

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type AsusServer struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (a *AsusServer) SetCategory(category ...string) {
	a.Category = model.Category.Server()
}

func (a *AsusServer) SetDeviceName(device ...string) {
	a.DeviceName = "Asus Server"
}

func (a *AsusServer) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.common_name": "Asus"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "Server"},
	}
}

func (a *AsusServer) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "server") && strings.Contains(strings.ToLower(val.(string)), "asus") {
			return true
		}
	}
	return false
}

func (a *AsusServer) DeviceScan(banner map[string]interface{}) bool {
	return false
}

func (a *AsusServer) CveScan(els *handler.Elastic) {}

func (a *AsusServer) PrintInfo() string { return model.Category.Server() + " | Asus Server" }

func (a *AsusServer) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    a.Category,
		DeviceName:  a.DeviceName,
		Version:     a.Version,
		CveList:     a.CveList,
		Sensibility: a.Sensibility,
		CveScore:    a.CveScore,
	}
}