package ubiquiti

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type Ubiquiti struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (u *Ubiquiti) SetCategory(category ...string) {
	u.Category = model.Category.Router()
}

func (u *Ubiquiti) SetDeviceName(device ...string) {
	u.DeviceName = "Ubiquiti"
}

func (u *Ubiquiti) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.common_name": "ubiquiti"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "ubiquiti"},
	}
}

func (u *Ubiquiti) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "ubiquiti") {
			return true
		}
	}
	return false
}

func (u *Ubiquiti) DeviceScan(banner map[string]interface{}) bool { return false }
func (u *Ubiquiti) CveScan(els *handler.Elastic)                  {}
func (u *Ubiquiti) PrintInfo() string                             { return model.Category.Router() + " | Ubiquiti" }

func (u *Ubiquiti) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    u.Category,
		DeviceName:  u.DeviceName,
		Version:     u.Version,
		CveList:     u.CveList,
		Sensibility: u.Sensibility,
		CveScore:    u.CveScore,
	}
}
