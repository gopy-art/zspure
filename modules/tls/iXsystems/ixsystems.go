package ixsystems

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type IXsystem struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (i *IXsystem) SetCategory(category ...string) {
	i.Category = model.Category.NetworkStorage()
}

func (i *IXsystem) SetDeviceName(device ...string) {
	i.DeviceName = "IXsystem"
}

func (i *IXsystem) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.issuer_dn": "iXsystems"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "iXsystems"},
	}
}

func (i *IXsystem) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "ixsystems") {
			return true
		}
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["issuer_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "ixsystems") {
			return true
		}
	}
	return false
}

func (i *IXsystem) DeviceScan(banner map[string]interface{}) bool { return false }
func (i *IXsystem) CveScan(els *handler.Elastic) {}
func (i *IXsystem) PrintInfo() string { return model.Category.NetworkStorage() + " | IXsystem" }

func (i *IXsystem) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    i.Category,
		DeviceName:  i.DeviceName,
		Version:     i.Version,
		CveList:     i.CveList,
		Sensibility: i.Sensibility,
		CveScore:    i.CveScore,
	}
}