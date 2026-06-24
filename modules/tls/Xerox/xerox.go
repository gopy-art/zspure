package xerox

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type Xerox struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (x *Xerox) SetCategory(category ...string) {
	x.Category = model.Category.Printer()
}

func (x *Xerox) SetDeviceName(device ...string) {
	x.DeviceName = "Xerox"
}

func (x *Xerox) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.issuer_dn": "Xerox Corporation"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "Xerox Corporation"},
	}
}

func (w *Xerox) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "xerox corporation") {
			return true
		}
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["issuer_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "xerox corporation") {
			return true
		}
	}
	return false
}

func (x *Xerox) DeviceScan(banner map[string]interface{}) bool { return false }
func (x *Xerox) CveScan(els *handler.Elastic) {}
func (x *Xerox) PrintInfo() string {
	return model.Category.Printer() + " | Xerox"
}

func (x *Xerox) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    x.Category,
		DeviceName:  x.DeviceName,
		Version:     x.Version,
		CveList:     x.CveList,
		Sensibility: x.Sensibility,
		CveScore:    x.CveScore,
	}
}