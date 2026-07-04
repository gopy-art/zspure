package dellcmc

import (
	"fmt"
	"strconv"
	"strings"
	"zspure/config"
	"zspure/config/cmd"
	"zspure/handler"
	"zspure/modules/model"
	"zspure/utils"
)

type DellCMC struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (d *DellCMC) SetCategory(category ...string) {
	d.Category = model.Category.Server()
}

func (d *DellCMC) SetDeviceName(device ...string) {
	d.DeviceName = "Dell CMC"
}

func (d *DellCMC) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.handshake_log.server_certificates.certificate.parsed.issuer_dn": "Dell Inc."},
		{"result.handshake_log.server_certificates.certificate.parsed.subject_dn": "cmc-33483"},
	}
}

func (d *DellCMC) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["subject_dn"].(string); ok {
		if strings.Contains(strings.ToLower(val), "dell inc.") && strings.Contains(strings.ToLower(val), "cmc-33483") {
			return true
		}
	}
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_certificates"].(map[string]interface{})["certificate"].(map[string]interface{})["parsed"].(map[string]interface{})["issuer_dn"].(string); ok {
		if strings.Contains(strings.ToLower(val), "dell inc.") && strings.Contains(strings.ToLower(val), "cmc-33483") {
			return true
		}
	}
	return false
}

func (d *DellCMC) DeviceScan(banner map[string]interface{}) bool {
	return false
}

func (c *DellCMC) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": c.DeviceName,
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
	} else if config.FIND_CVE {
		url := fmt.Sprintf(model.CVE.MainResource(), "dell"+"%20"+"cmc")
		recieve, err := utils.GatherCVEOnline(url)
		if err != nil {
			cmd.ErrorLogger.Println("[CVE] error in gather the CVE for this device. (Server error)")
			return
		}
		CVE = append(CVE, recieve...)
	}

	if len(CVE) == 0 {
		cmd.InfoLogger.Println("[CVE] do not find any CVE for this module.")
		return
	}

	for _, vl := range CVE {
		c.CveList = append(c.CveList, vl.CVEID)
		totalScore += vl.BaseScore
	}

	c.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if c.CveScore > 7 {
		c.Sensibility = "HIGH"
	} else if c.CveScore >= 4 && c.CveScore <= 7 {
		c.Sensibility = "MEDIUM"
	} else if c.CveScore < 4 {
		c.Sensibility = "LOW"
	}
	c.CveList = utils.RemoveDuplicates(c.CveList)
}

func (d *DellCMC) PrintInfo() string { return model.Category.Server() + " | Dell CMC" }

func (d *DellCMC) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    d.Category,
		DeviceName:  d.DeviceName,
		Version:     d.Version,
		CveList:     d.CveList,
		Sensibility: d.Sensibility,
		CveScore:    d.CveScore,
	}
}
