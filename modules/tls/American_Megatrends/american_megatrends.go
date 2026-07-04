package americanmegatrends

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type AmericanMegatrends struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (a *AmericanMegatrends) SetCategory(category ...string) {
	a.Category = model.Category.Service()
}

func (a *AmericanMegatrends) SetDeviceName(device ...string) {
	a.DeviceName = "American Megatrends"
}

func (a *AmericanMegatrends) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsea.subject_dn": "American Megatrends"},
		{"result.handshake_log.server_certificates.certificate.parsea.issuer_dn": "American Megatrends"},
	}
}

func (a *AmericanMegatrends) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["issuer_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "american megatrends") {
			return true
		}
	}	
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "american megatrends") {
			return true
		}
	}
	return false
}

func (a *AmericanMegatrends) DeviceScan(banner map[string]interface{}) bool {
	return false
}

func (a *AmericanMegatrends) CveScan(els *handler.Elastic) {}

func (a *AmericanMegatrends) PrintInfo() string { return model.Category.Service() + " | American Megatrends" }

func (a *AmericanMegatrends) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    a.Category,
		DeviceName:  a.DeviceName,
		Version:     a.Version,
		CveList:     a.CveList,
		Sensibility: a.Sensibility,
		CveScore:    a.CveScore,
	}
}
