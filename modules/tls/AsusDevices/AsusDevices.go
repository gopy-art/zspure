package asusdevices

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type AsusDevices struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (a *AsusDevices) SetCategory(category ...string) {
	a.Category = model.Category.Device()
}

func (a *AsusDevices) SetDeviceName(device ...string) {
	a.DeviceName = "Asus Devices"
}

func (a *AsusDevices) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "asus"},
	}
}

func (a *AsusDevices) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "asus") && !(strings.Contains(strings.ToLower(val.(string)), "router") || strings.Contains(strings.ToLower(val.(string)), "server")) {
			return true
		}
	}
	return false
}

func (a *AsusDevices) DeviceScan(banner map[string]interface{}) bool {
	return false
}

func (a *AsusDevices) CveScan(els *handler.Elastic) {}

func (a *AsusDevices) PrintInfo() string { return model.Category.Device() + " | Asus Devices" }

func (a *AsusDevices) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    a.Category,
		DeviceName:  a.DeviceName,
		Version:     a.Version,
		CveList:     a.CveList,
		Sensibility: a.Sensibility,
		CveScore:    a.CveScore,
	}
}