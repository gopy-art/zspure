package dell

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type Dell struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (d *Dell) SetCategory(category ...string) {
	d.Category = model.Category.Printer()
}

func (d *Dell) SetDeviceName(device ...string) {
	d.DeviceName = "Dell"
}

func (d *Dell) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.issuer_dn": "Dell"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "Dell"},
	}
}

func (d *Dell) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"].(string); ok {
		if strings.Contains(strings.ToLower(val), "dell") {
			return true
		}
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["issuer_dn"].(string); ok {
		if strings.Contains(strings.ToLower(val), "dell") {
			return true
		}
	}
	return false
}

func (d *Dell) DeviceScan(banner map[string]interface{}) bool { return false }
func (d *Dell) CveScan(els *handler.Elastic)                  {}
func (d *Dell) PrintInfo() string                             { return model.Category.Printer() + " | Dell" }

func (d *Dell) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    d.Category,
		DeviceName:  d.DeviceName,
		Version:     d.Version,
		CveList:     d.CveList,
		Sensibility: d.Sensibility,
		CveScore:    d.CveScore,
	}
}
