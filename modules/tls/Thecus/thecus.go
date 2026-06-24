package thecus

import (
	"regexp"
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type ThecusNAS struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
}

func (t *ThecusNAS) SetCategory(category ...string) {
	t.Category = model.Category.NetworkStorage()
}

func (t *ThecusNAS) SetDeviceName(device ...string) {
	t.DeviceName = "Thecus"
}

func (t *ThecusNAS) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.issuer_dn": "Thecus Technology Corp."},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "Thecus Technology Corp."},
	}
}

func (t *ThecusNAS) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "thecus technology corp.") {
			return true
		}
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["issuer_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "thecus technology corp.") {
			return true
		}
	}
	return false
}

func (t *ThecusNAS) DeviceScan(banner map[string]interface{}) bool {
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		re := regexp.MustCompile(`OU=([A-Za-z0-9\-]+)`)
		matches := re.FindStringSubmatch(val.(string))
		if len(matches) > 1 {
			t.Version = matches[1]
		}
	}
	return false
}

func (t *ThecusNAS) CveScan(els *handler.Elastic) {}
func (t *ThecusNAS) PrintInfo() string {
	return model.Category.NetworkStorage() + " | Thecus"
}

func (t *ThecusNAS) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         t.Category,
		DeviceName:       t.DeviceName,
		Version:          t.Version,
		CveList:          t.CveList,
		Sensibility:      t.Sensibility,
		CveScore:         t.CveScore,
	}
}
