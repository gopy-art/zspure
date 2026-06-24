package lifesize

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type LifeSizeTransitServer struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (l *LifeSizeTransitServer) SetCategory(category ...string) {
	l.Category = model.Category.Service()
}

func (l *LifeSizeTransitServer) SetDeviceName(device ...string) {
	l.DeviceName = "LifeSize Transit Server"
}

func (l *LifeSizeTransitServer) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.issuer_dn": "LifeSize Transit Server"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "LifeSize Transit Server"},
	}
}

func (l *LifeSizeTransitServer) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "lifesize transit server") {
			return true
		}
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["issuer_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "lifesize transit server") {
			return true
		}
	}
	return false
}

func (l *LifeSizeTransitServer) DeviceScan(banner map[string]interface{}) bool { return false }
func (l *LifeSizeTransitServer) CveScan(els *handler.Elastic)                  {}
func (l *LifeSizeTransitServer) PrintInfo() string                             { return model.Category.Service() + " | LifeSize Transit Server" }

func (l *LifeSizeTransitServer) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    l.Category,
		DeviceName:  l.DeviceName,
		Version:     l.Version,
		CveList:     l.CveList,
		Sensibility: l.Sensibility,
		CveScore:    l.CveScore,
	}
}
