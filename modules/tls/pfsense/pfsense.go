package pfsense

import (
	"fmt"
	"strconv"
	"strings"
	"zspure/handler"
	"zspure/modules/model"
	"zspure/utils"
)

type Pfsense struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (p *Pfsense) SetCategory(category ...string) {
	p.Category = model.Category.Firewall()
}

func (p *Pfsense) SetDeviceName(device ...string) {
	p.DeviceName = "pfsense"
}

func (p *Pfsense) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.subject.common_name": "pfsense"},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "pfsense"},
	}
}

func (p *Pfsense) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "pfsense") {
			return true
		}
	}
	return false
}

func (p *Pfsense) DeviceScan(banner map[string]interface{}) bool {
	return false
}

func (p *Pfsense) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0
	result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{"cve.descriptions.value": fmt.Sprintf("%s %s", p.DeviceName, p.Version)}))
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
		p.CveList = append(p.CveList, v.CVEID)
		totalScore += v.BaseScore
	}

	p.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if p.CveScore > 7 {
		p.Sensibility = "HIGH"
	} else if p.CveScore >= 4 && p.CveScore <= 7 {
		p.Sensibility = "MEDIUM"
	} else if p.CveScore < 4 {
		p.Sensibility = "LOW"
	}
	p.CveList = utils.RemoveDuplicates(p.CveList)
}

func (p *Pfsense) PrintInfo() string { return model.Category.Firewall() + " | pfsense" }

func (p *Pfsense) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    p.Category,
		DeviceName:  p.DeviceName,
		Version:     p.Version,
		CveList:     p.CveList,
		Sensibility: p.Sensibility,
		CveScore:    p.CveScore,
	}
}