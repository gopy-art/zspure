package opto22

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

type Opto22 struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (o *Opto22) SetCategory(category ...string) {
	o.Category = model.Category.Industrial()
}

func (o *Opto22) SetDeviceName(device ...string) {
	o.DeviceName = "Opto22"
}

func (o *Opto22) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (o *Opto22) Filters(banner map[string]interface{}) bool {
	if banner["banner"] != nil && banner["banner"].(string) != "" && strings.Contains(strings.ToLower(banner["banner"].(string)), strings.ToLower("Opto 22 FTP server")) {
		return true
	}
	return false
}

func (o *Opto22) DeviceScan(banner map[string]interface{}) bool {
	return false
}

func (o *Opto22) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": fmt.Sprintf("%v", o.DeviceName),
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
		url := fmt.Sprintf(model.CVE.MainResource(),
			strings.ToLower(strings.ReplaceAll(fmt.Sprintf("%v", o.DeviceName), " ", "%20")))
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

	for _, v := range CVE {
		o.CveList = append(o.CveList, v.CVEID)
		totalScore += v.BaseScore
	}

	o.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if o.CveScore > 7 {
		o.Sensibility = "HIGH"
	} else if o.CveScore >= 4 && o.CveScore <= 7 {
		o.Sensibility = "MEDIUM"
	} else if o.CveScore < 4 {
		o.Sensibility = "LOW"
	}
	o.CveList = utils.RemoveDuplicates(o.CveList)
}

func (o *Opto22) PrintInfo() string {
	return model.Category.Industrial() + " | Opto22"
}

func (o *Opto22) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    o.Category,
		DeviceName:  o.DeviceName,
		Version:     o.Version,
		CveList:     o.CveList,
		Sensibility: o.Sensibility,
		CveScore:    o.CveScore,
	}
}