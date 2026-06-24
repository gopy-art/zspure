package grandstream

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type GrandStream struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (g *GrandStream) SetCategory(category ...string) {
	g.Category = model.Category.Router()
}

func (g *GrandStream) SetDeviceName(device ...string) {
	g.DeviceName = "GrandStream"
}

func (g *GrandStream) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.common_name": "grandstream"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "grandstream"},
	}
}

func (g *GrandStream) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "grandstream") {
			return true
		}
	}
	return false
}

func (g *GrandStream) DeviceScan(banner map[string]interface{}) bool {
	return false
}

func (g *GrandStream) CveScan(els *handler.Elastic) {}

func (g *GrandStream) PrintInfo() string { return model.Category.Router() + " | GrandStream" }

func (g *GrandStream) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    g.Category,
		DeviceName:  g.DeviceName,
		Version:     g.Version,
		CveList:     g.CveList,
		Sensibility: g.Sensibility,
		CveScore:    g.CveScore,
	}
}