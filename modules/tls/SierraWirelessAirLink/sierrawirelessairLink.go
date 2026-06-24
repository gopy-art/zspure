package sierrawirelessairlink

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type SierraWirelessAirLink struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (s *SierraWirelessAirLink) SetCategory(category ...string) {
	s.Category = model.Category.Router()
}

func (s *SierraWirelessAirLink) SetDeviceName(device ...string) {
	s.DeviceName = "Sierra Wireless AirLink"
}

func (s *SierraWirelessAirLink) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.common_name": "sierra"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "sierra"},
	}
}

func (s *SierraWirelessAirLink) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "sierra") {
			return true
		}
	}
	return false
}

func (s *SierraWirelessAirLink) DeviceScan(banner map[string]interface{}) bool { return false }
func (s *SierraWirelessAirLink) CveScan(els *handler.Elastic)                  {}
func (s *SierraWirelessAirLink) PrintInfo() string                             { return model.Category.Router() + " | Sierra Wireless AirLink" }

func (s *SierraWirelessAirLink) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    s.Category,
		DeviceName:  s.DeviceName,
		Version:     s.Version,
		CveList:     s.CveList,
		Sensibility: s.Sensibility,
		CveScore:    s.CveScore,
	}
}
