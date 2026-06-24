package zte

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type ZTEGateway struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (z *ZTEGateway) SetCategory(category ...string) {
	z.Category = model.Category.Router()
}

func (z *ZTEGateway) SetDeviceName(device ...string) {
	z.DeviceName = "ZTE Router Panel"
}

func (z *ZTEGateway) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.common_name": "ZTE"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "ZTE"},
	}
}

func (z *ZTEGateway) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "zte") {
			return true
		}
	}
	return false
}

func (z *ZTEGateway) DeviceScan(banner map[string]interface{}) bool {
	return false
}

func (z *ZTEGateway) CveScan(els *handler.Elastic) {}

func (z *ZTEGateway) PrintInfo() string { return model.Category.Router() + " | ZTE Router Panel" }

func (z *ZTEGateway) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    z.Category,
		DeviceName:  z.DeviceName,
		Version:     z.Version,
		CveList:     z.CveList,
		Sensibility: z.Sensibility,
		CveScore:    z.CveScore,
	}
}