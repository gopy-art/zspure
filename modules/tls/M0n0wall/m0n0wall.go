package m0n0wall

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type M0n0wallFreeBSD struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (m *M0n0wallFreeBSD) SetCategory(category ...string) {
	m.Category = model.Category.Firewall()
}

func (m *M0n0wallFreeBSD) SetDeviceName(device ...string) {
	m.DeviceName = "m0n0wall FreeBSD"
}

func (m *M0n0wallFreeBSD) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.common_name": "m0n0wall"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "m0n0wall"},
	}
}

func (m *M0n0wallFreeBSD) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "m0n0wall") {
			return true
		}
	}
	return false
}

func (m *M0n0wallFreeBSD) DeviceScan(banner map[string]interface{}) bool {
	return false
}

func (m *M0n0wallFreeBSD) CveScan(els *handler.Elastic) {}

func (m *M0n0wallFreeBSD) PrintInfo() string { return model.Category.Firewall() + " | m0n0wall FreeBSD" }

func (m *M0n0wallFreeBSD) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    m.Category,
		DeviceName:  m.DeviceName,
		Version:     m.Version,
		CveList:     m.CveList,
		Sensibility: m.Sensibility,
		CveScore:    m.CveScore,
	}
}