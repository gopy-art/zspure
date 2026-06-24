package pptpvpn

import (
	"fmt"
	"strconv"
	"strings"
	"zspure/handler"
	"zspure/modules/model"
	"zspure/utils"
)

type PPTPVPN struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (p *PPTPVPN) SetCategory(category ...string) {
	p.Category = model.Category.VPN()
}

func (p *PPTPVPN) SetDeviceName(device ...string) {
	p.DeviceName = ""
}

func (a *PPTPVPN) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (p *PPTPVPN) Filters(banner map[string]interface{}) bool {
	if banner["VendorName"] == nil || banner["HostName"] == nil {
		return false
	}
	if vhost, ok := banner["HostName"].(string); ok {
		if vendor, ok := banner["VendorName"].(string); ok {
			if vhost != "" && vendor != "" {
				return true
			}
		}
	}
	return false
}

func (p *PPTPVPN) DeviceScan(banner map[string]interface{}) bool {
	var vendorName string
	if val, ok := banner["VendorName"].(string); ok && val != "" {
		vendorName = val
	}

	if strings.Contains(vendorName, "Cisco Systems, Inc.") {
		vendorName = strings.Fields(vendorName)[0]
	}

	p.DeviceName = fmt.Sprintf("%v VPN", vendorName)
	return false
}

func (p *PPTPVPN) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0
	result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
		"cve.descriptions.value": p.DeviceName,
	}))
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

func (p *PPTPVPN) PrintInfo() string { return model.Category.VPN() + " | pptp vpns" }

func (p *PPTPVPN) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    p.Category,
		DeviceName:  p.DeviceName,
		Version:     p.Version,
		CveList:     p.CveList,
		Sensibility: p.Sensibility,
		CveScore:    p.CveScore,
	}
}
