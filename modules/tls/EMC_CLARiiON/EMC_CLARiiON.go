package emcclariion

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type EmcClariion struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (e *EmcClariion) SetCategory(category ...string) {
	e.Category = model.Category.NetworkStorage()
}

func (e *EmcClariion) SetDeviceName(device ...string) {
	e.DeviceName = "EMC CLARiiON"
}

func (e *EmcClariion) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.issuer_dn": "CLARiiON"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "CLARiiON"},
	}
}

func (e *EmcClariion) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["issuer_dn"].(string); ok {
		if strings.Contains(strings.ToLower(val), "emc") && strings.Contains(strings.ToLower(val), "clariion") {
			return true
		}
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"].(string); ok {
		if strings.Contains(strings.ToLower(val), "emc") && strings.Contains(strings.ToLower(val), "clariion") {
			return true
		}
	}
	return false
}

func (e *EmcClariion) DeviceScan(banner map[string]interface{}) bool { return false }
func (e *EmcClariion) CveScan(els *handler.Elastic)                  {}
func (e *EmcClariion) PrintInfo() string                             { return model.Category.NetworkStorage() + " | EMC CLARiiON" }

func (e *EmcClariion) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    e.Category,
		DeviceName:  e.DeviceName,
		Version:     e.Version,
		CveList:     e.CveList,
		Sensibility: e.Sensibility,
		CveScore:    e.CveScore,
	}
}
