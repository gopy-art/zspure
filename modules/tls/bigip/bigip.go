package bigip

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type Bigip struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (b *Bigip) SetCategory(category ...string) {
	b.Category = model.Category.Camera()
}

func (b *Bigip) SetDeviceName(device ...string) {
	b.DeviceName = "BigIp"
}

func (b *Bigip) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "bigip"},
		{"result.handshake_log.server_certificates.certificate.parsed.issuer_dn": "bigip"},
	}
}

func (b *Bigip) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["issuer_dn"].(string); ok {
		if strings.Contains(strings.ToLower(val), "bigip") {
			return true
		}
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"].(string); ok {
		if strings.Contains(strings.ToLower(val), "bigip") {
			return true
		}
	}
	return false
}

func (b *Bigip) DeviceScan(banner map[string]interface{}) bool {
	return false
}

func (b *Bigip) CveScan(els *handler.Elastic) {}

func (b *Bigip) PrintInfo() string { return model.Category.Camera() + " | BigIp" }

func (b *Bigip) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    b.Category,
		DeviceName:  b.DeviceName,
		Version:     b.Version,
		CveList:     b.CveList,
		Sensibility: b.Sensibility,
		CveScore:    b.CveScore,
	}
}
