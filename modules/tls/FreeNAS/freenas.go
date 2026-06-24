package freenas

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type FreeNAS struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (f *FreeNAS) SetCategory(category ...string) {
	f.Category = model.Category.NetworkStorage()
}

func (f *FreeNAS) SetDeviceName(device ...string) {
	f.DeviceName = "FreeNAS"
}

func (f *FreeNAS) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.common_name": "FreeNAS"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "FreeNAS"},
	}
}

func (f *FreeNAS) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "freenas") {
			return true
		}
	}
	return false
}

func (f *FreeNAS) DeviceScan(banner map[string]interface{}) bool { return false }
func (f *FreeNAS) CveScan(els *handler.Elastic)                  {}
func (f *FreeNAS) PrintInfo() string                             { return model.Category.NetworkStorage() + " | FreeNAS" }

func (f *FreeNAS) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    f.Category,
		DeviceName:  f.DeviceName,
		Version:     f.Version,
		CveList:     f.CveList,
		Sensibility: f.Sensibility,
		CveScore:    f.CveScore,
	}
}