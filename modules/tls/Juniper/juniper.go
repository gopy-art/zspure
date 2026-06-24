package juniper

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type JuniperNetworks struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (j *JuniperNetworks) SetCategory(category ...string) {
	j.Category = model.Category.Router()
}

func (j *JuniperNetworks) SetDeviceName(device ...string) {
	j.DeviceName = "Juniper TLS Network"
}

func (j *JuniperNetworks) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.common_name": "Juniper"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "Juniper"},
	}
}

func (j *JuniperNetworks) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "juniper") {
			return true
		}
	}
	return false
}

func (j *JuniperNetworks) DeviceScan(banner map[string]interface{}) bool {
	return false
}

func (j *JuniperNetworks) CveScan(els *handler.Elastic) {}

func (j *JuniperNetworks) PrintInfo() string { return model.Category.Router() + " | Juniper TLS Network" }

func (j *JuniperNetworks) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    j.Category,
		DeviceName:  j.DeviceName,
		Version:     j.Version,
		CveList:     j.CveList,
		Sensibility: j.Sensibility,
		CveScore:    j.CveScore,
	}
}