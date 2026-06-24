package ami

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type AMI struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (a *AMI) SetCategory(category ...string) {
	a.Category = model.Category.Industrial()
}

func (a *AMI) SetDeviceName(device ...string) {
	a.DeviceName = "AMI TLS Panel"
}

func (a *AMI) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.common_name": "AMI"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "AMI"},
	}
}

func (a *AMI) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "ami") {
			return true
		}
	}
	return false
}

func (a *AMI) DeviceScan(banner map[string]interface{}) bool {
	return false
}

func (a *AMI) CveScan(els *handler.Elastic) {}

func (a *AMI) PrintInfo() string { return model.Category.Industrial() + " | AMI TLS Panel" }

func (a *AMI) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    a.Category,
		DeviceName:  a.DeviceName,
		Version:     a.Version,
		CveList:     a.CveList,
		Sensibility: a.Sensibility,
		CveScore:    a.CveScore,
	}
}