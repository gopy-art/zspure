package jetdirect

import (
	"regexp"
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type JetDirect struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (j *JetDirect) SetCategory(category ...string) {
	j.Category = model.Category.Printer()
}

func (j *JetDirect) SetDeviceName(device ...string) {
	j.DeviceName = "HP Jetdirect"
}

func (j *JetDirect) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.issuer_dn": "HP Jetdirect"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "HP Jetdirect"},
	}
}

func (j *JetDirect) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "hp jetdirect") {
			return true
		}
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["issuer_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "hp jetdirect") {
			return true
		}
	}
	return false
}

func (j *JetDirect) DeviceScan(banner map[string]interface{}) bool {
	var cn string
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		cn = val.(string)
	}

	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["issuer_dn"]; ok {
		cn = val.(string)
	}

	re := regexp.MustCompile(`CN=HP Jetdirect ([A-Z0-9]+)`)
    matches := re.FindStringSubmatch(cn)
    if len(matches) > 1 {
        j.Version = matches[1]
		return true
    }

	return false
}

func (j *JetDirect) CveScan(els *handler.Elastic) {}
func (j *JetDirect) PrintInfo() string { return model.Category.Printer() + " | HP Jetdirect" }

func (j *JetDirect) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    j.Category,
		DeviceName:  j.DeviceName,
		Version:     j.Version,
		CveList:     j.CveList,
		Sensibility: j.Sensibility,
		CveScore:    j.CveScore,
	}
}