package polycom

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type PolycomCamera struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (p *PolycomCamera) SetCategory(category ...string) {
	p.Category = model.Category.Camera()
}

func (p *PolycomCamera) SetDeviceName(device ...string) {
	p.DeviceName = "Polycom"
}

func (p *PolycomCamera) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.common_name": "Polycom"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "Polycom"},
	}
}

func (p *PolycomCamera) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "polycom") {
			return true
		}
	}
	return false
}

func (p *PolycomCamera) DeviceScan(banner map[string]interface{}) bool { return false }
func (p *PolycomCamera) CveScan(els *handler.Elastic)                  {}
func (p *PolycomCamera) PrintInfo() string                             { return model.Category.Camera() + " | Polycom" }

func (p *PolycomCamera) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    p.Category,
		DeviceName:  p.DeviceName,
		Version:     p.Version,
		CveList:     p.CveList,
		Sensibility: p.Sensibility,
		CveScore:    p.CveScore,
	}
}