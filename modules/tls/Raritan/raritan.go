package raritan

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type Raritan struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (r *Raritan) SetCategory(category ...string) {
	r.Category = model.Category.Network()
}

func (r *Raritan) SetDeviceName(device ...string) {
	r.DeviceName = "Raritan"
}

func (r *Raritan) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.issuer_dn": "Raritan"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "Raritan"},
	}
}

func (r *Raritan) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "raritan") {
			return true
		}
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["issuer_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "raritan") {
			return true
		}
	}
	return false
}

func (r *Raritan) DeviceScan(banner map[string]interface{}) bool {
	r.ExtraInformation.NewExtraInfo()
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "raritan kvm") {
			r.ExtraInformation.SetExtraInfo("product", "KVM")
		}
	}
	return false
}

func (r *Raritan) CveScan(els *handler.Elastic) {}
func (r *Raritan) PrintInfo() string            { return model.Category.Network() + " | Raritan" }

func (r *Raritan) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         r.Category,
		DeviceName:       r.DeviceName,
		Version:          r.Version,
		CveList:          r.CveList,
		Sensibility:      r.Sensibility,
		CveScore:         r.CveScore,
		ExtraInformation: r.ExtraInformation,
	}
}
