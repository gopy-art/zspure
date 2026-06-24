package terramaster

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type TerraMaster struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (t *TerraMaster) SetCategory(category ...string) {
	t.Category = model.Category.NetworkStorage()
}

func (t *TerraMaster) SetDeviceName(device ...string) {
	t.DeviceName = "TerraMaster"
}

func (t *TerraMaster) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.common_name": "TerraMaster"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "TerraMaster"},
	}
}

func (t *TerraMaster) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "terramaster") {
			return true
		}
	}
	return false
}

func (t *TerraMaster) DeviceScan(banner map[string]interface{}) bool { return false }
func (t *TerraMaster) CveScan(els *handler.Elastic) {}
func (t *TerraMaster) PrintInfo() string { return model.Category.NetworkStorage() + " | TerraMaster" }

func (t *TerraMaster) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    t.Category,
		DeviceName:  t.DeviceName,
		Version:     t.Version,
		CveList:     t.CveList,
		Sensibility: t.Sensibility,
		CveScore:    t.CveScore,
	}
}