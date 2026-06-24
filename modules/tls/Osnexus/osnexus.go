package osnexus

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type OsnexusStorage struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (o *OsnexusStorage) SetCategory(category ...string) {
	o.Category = model.Category.NetworkStorage()
}

func (o *OsnexusStorage) SetDeviceName(device ...string) {
	o.DeviceName = "Osnexus"
}

func (o *OsnexusStorage) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.issuer_dn": "OSNEXUS"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "OSNEXUS"},
	}
}

func (o *OsnexusStorage) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "osnexus") {
			return true
		}
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["issuer_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "osnexus") {
			return true
		}
	}
	return false
}

func (o *OsnexusStorage) DeviceScan(banner map[string]interface{}) bool {
	o.ExtraInformation.NewExtraInfo()
	o.ExtraInformation.SetExtraInfo("product", "Quantator")
	return false
}

func (o *OsnexusStorage) CveScan(els *handler.Elastic) {}
func (o *OsnexusStorage) PrintInfo() string {
	return model.Category.NetworkStorage() + " | Osnexus"
}

func (o *OsnexusStorage) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         o.Category,
		DeviceName:       o.DeviceName,
		Version:          o.Version,
		CveList:          o.CveList,
		Sensibility:      o.Sensibility,
		CveScore:         o.CveScore,
		ExtraInformation: o.ExtraInformation,
	}
}
