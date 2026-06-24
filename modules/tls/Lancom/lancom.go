package lancom

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type Lancom struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (l *Lancom) SetCategory(category ...string) {
	l.Category = model.Category.Router()
}

func (l *Lancom) SetDeviceName(device ...string) {
	l.DeviceName = "Lancom"
}

func (l *Lancom) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.common_name": "LANCOM"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "LANCOM"},
	}
}

func (l *Lancom) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "lancom") {
			return true
		}
	}
	return false
}

func (l *Lancom) DeviceScan(banner map[string]interface{}) bool {
	return false
}

func (l *Lancom) CveScan(els *handler.Elastic) {}

func (l *Lancom) PrintInfo() string { return model.Category.Router() + " | Lancom" }

func (l *Lancom) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    l.Category,
		DeviceName:  l.DeviceName,
		Version:     l.Version,
		CveList:     l.CveList,
		Sensibility: l.Sensibility,
		CveScore:    l.CveScore,
	}
}