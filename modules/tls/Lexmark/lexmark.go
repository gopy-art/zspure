package lexmark

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type Lexmark struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (l *Lexmark) SetCategory(category ...string) {
	l.Category = model.Category.Printer()
}

func (l *Lexmark) SetDeviceName(device ...string) {
	l.DeviceName = "Lexmark"
}

func (l *Lexmark) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.issuer_dn": "Lexmark"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "Lexmark"},
	}
}

func (l *Lexmark) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "lexmark") {
			return true
		}
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["issuer_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "lexmark") {
			return true
		}
	}
	return false
}

func (l *Lexmark) DeviceScan(banner map[string]interface{}) bool { return false }
func (l *Lexmark) CveScan(els *handler.Elastic)                  {}
func (l *Lexmark) PrintInfo() string                             { return model.Category.Printer() + " | Lexmark" }

func (l *Lexmark) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    l.Category,
		DeviceName:  l.DeviceName,
		Version:     l.Version,
		CveList:     l.CveList,
		Sensibility: l.Sensibility,
		CveScore:    l.CveScore,
	}
}
