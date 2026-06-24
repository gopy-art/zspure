package fortinet

import (
	"fmt"
	"strconv"
	"strings"
	"zspure/handler"
	"zspure/modules/model"
	"zspure/utils"
)

type Fortinet struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (f *Fortinet) SetCategory(category ...string) {
	f.Category = model.Category.Firewall()
}

func (f *Fortinet) SetDeviceName(device ...string) {
	f.DeviceName = "Fortinet"
}

func (a *Fortinet) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.common_name": "FortiGate"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "Fortinet"},
	}
}

func (f *Fortinet) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(val.(string), "Fortinet") ||
			strings.Contains(val.(string), "FortiGate") {
			return true
		}
	}
	return false
}

func (f *Fortinet) DeviceScan(banner map[string]interface{}) bool {
	return false
}

func (f *Fortinet) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0
	result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{"cve.descriptions.value": fmt.Sprintf("%s %s", f.DeviceName, f.Version)}))
	if len(result) == 0 {
		return
	}
	for _, c := range result {
		if len(CVE) == 10 {
			break
		}
		cveMod := model.NewCVEStructure(c)
		CVE = append(CVE, cveMod)
	}

	for _, v := range CVE {
		f.CveList = append(f.CveList, v.CVEID)
		totalScore += v.BaseScore
	}

	f.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if f.CveScore > 7 {
		f.Sensibility = "HIGH"
	} else if f.CveScore >= 4 && f.CveScore <= 7 {
		f.Sensibility = "MEDIUM"
	} else if f.CveScore < 4 {
		f.Sensibility = "LOW"
	}
	f.CveList = utils.RemoveDuplicates(f.CveList)
}

func (f *Fortinet) PrintInfo() string { return model.Category.Firewall() + " | Fortinet Login" }

func (f *Fortinet) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    f.Category,
		DeviceName:  f.DeviceName,
		Version:     f.Version,
		CveList:     f.CveList,
		Sensibility: f.Sensibility,
		CveScore:    f.CveScore,
	}
}
