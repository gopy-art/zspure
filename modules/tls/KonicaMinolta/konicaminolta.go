package konicaminolta

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type KonicaMinolta struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (k *KonicaMinolta) SetCategory(category ...string) {
	k.Category = model.Category.Printer()
}

func (k *KonicaMinolta) SetDeviceName(device ...string) {
	k.DeviceName = "Konica Minolta"
}

func (k *KonicaMinolta) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.issuer_dn": "Konica Minolta"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "Konica Minolta"},
	}
}

func (k *KonicaMinolta) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "konica minolta") {
			return true
		}
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["issuer_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "konica minolta") {
			return true
		}
	}
	return false
}

func (k *KonicaMinolta) DeviceScan(banner map[string]interface{}) bool { return false }
func (k *KonicaMinolta) CveScan(els *handler.Elastic) {}
func (k *KonicaMinolta) PrintInfo() string { return model.Category.Printer() + " | Konica Minolta" }

func (k *KonicaMinolta) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    k.Category,
		DeviceName:  k.DeviceName,
		Version:     k.Version,
		CveList:     k.CveList,
		Sensibility: k.Sensibility,
		CveScore:    k.CveScore,
	}
}