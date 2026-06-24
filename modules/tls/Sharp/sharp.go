package sharp

import (
	"regexp"
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type Sharp struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (s *Sharp) SetCategory(category ...string) {
	s.Category = model.Category.Printer()
}

func (s *Sharp) SetDeviceName(device ...string) {
	s.DeviceName = "Sharp"
}

func (s *Sharp) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.issuer_dn": "Sharp Corporation"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "Sharp Corporation"},
	}
}

func (s *Sharp) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "sharp corporation") {
			return true
		}
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["issuer_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "sharp corporation") {
			return true
		}
	}
	return false
}

func (s *Sharp) DeviceScan(banner map[string]interface{}) bool {
	s.ExtraInformation.NewExtraInfo()
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		re := regexp.MustCompile(`CN=SHARP\s+([A-Za-z0-9\-]+)`)
		matches := re.FindStringSubmatch(val.(string))
		if len(matches) > 1 {
			s.ExtraInformation.SetExtraInfo("model", matches[1])
		}
	}
	return false
}

func (s *Sharp) CveScan(els *handler.Elastic) {}
func (s *Sharp) PrintInfo() string            { return model.Category.Printer() + " | Sharp" }

func (s *Sharp) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         s.Category,
		DeviceName:       s.DeviceName,
		Version:          s.Version,
		CveList:          s.CveList,
		Sensibility:      s.Sensibility,
		CveScore:         s.CveScore,
		ExtraInformation: s.ExtraInformation,
	}
}
