package uniview

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type UniviewCamera struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (u *UniviewCamera) SetCategory(category ...string) {
	u.Category = model.Category.Camera()
}

func (u *UniviewCamera) SetDeviceName(device ...string) {
	u.DeviceName = "Uniview"
}

func (u *UniviewCamera) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.common_name": "Uniview"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "Uniview"},
	}
}

func (u *UniviewCamera) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "uniview") {
			return true
		}
	}
	return false
}

func (u *UniviewCamera) DeviceScan(banner map[string]interface{}) bool { return false }
func (u *UniviewCamera) CveScan(els *handler.Elastic)                  {}
func (u *UniviewCamera) PrintInfo() string                             { return model.Category.Camera() + " | Uniview" }

func (u *UniviewCamera) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    u.Category,
		DeviceName:  u.DeviceName,
		Version:     u.Version,
		CveList:     u.CveList,
		Sensibility: u.Sensibility,
		CveScore:    u.CveScore,
	}
}
