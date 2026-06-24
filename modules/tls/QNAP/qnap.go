package qnap

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type QNAPNAS struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (q *QNAPNAS) SetCategory(category ...string) {
	q.Category = model.Category.NetworkStorage()
}

func (q *QNAPNAS) SetDeviceName(device ...string) {
	q.DeviceName = "QNAP NAS"
}

func (q *QNAPNAS) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.common_name": "QNAP"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "QNAP"},
	}
}

func (q *QNAPNAS) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "qnap") {
			return true
		}
	}
	return false
}

func (q *QNAPNAS) DeviceScan(banner map[string]interface{}) bool { return false }
func (q *QNAPNAS) CveScan(els *handler.Elastic)                  {}
func (q *QNAPNAS) PrintInfo() string                             { return model.Category.NetworkStorage() + " | QNAP NAS" }

func (q *QNAPNAS) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    q.Category,
		DeviceName:  q.DeviceName,
		Version:     q.Version,
		CveList:     q.CveList,
		Sensibility: q.Sensibility,
		CveScore:    q.CveScore,
	}
}