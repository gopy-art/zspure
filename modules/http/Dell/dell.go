package dell

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

type Dell struct {
	Category    string                `json:"dvs_category"`
	DeviceName  string                `json:"device_name"`
	Version     string                `json:"version"`
	CveList     []string              `json:"cves"`
	Sensibility string                `json:"base_severity"`
	CveScore    float64               `json:"cve_score"`
	ExtraInfo   model.ModuleExtraInfo `json:"dvs_extra"`
}

func (d *Dell) SetCategory(category ...string) {
	d.Category = model.Category.Printer()
}

func (d *Dell) SetDeviceName(device ...string) {
	d.DeviceName = "Dell"
}

func (a *Dell) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (d *Dell) Filters(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	if val, ok := banner["response"].(map[string]interface{})["body"].(string); ok {
		if (strings.Contains(val, "Dell") &&
			strings.Contains(val, "Laser Printer")) &&
			!strings.Contains(val, "0<!DOCTYPE html>") &&
			!strings.Contains(val, "<p hidden>") {
			return true
		}
	}
	return false
}

func (d *Dell) DeviceScan(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	d.ExtraInfo.NewExtraInfo()
	if val, ok := banner["response"].(map[string]interface{})["title"]; ok {
		valStr := fmt.Sprintf("%v", val)
		if strings.Contains(valStr, "Dell") && strings.Contains(valStr, "Laser Printer") {
			d.ExtraInfo.SetExtraInfo("product", strings.Split(valStr, "Dell")[1])
			return true
		}
	}
	return false
}

func (d *Dell) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": d.DeviceName,
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
		url := fmt.Sprintf(model.CVE.MainResource(), d.DeviceName)
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
		d.CveList = append(d.CveList, v.CVEID)
		totalScore += v.BaseScore
	}

	d.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if d.CveScore > 7 {
		d.Sensibility = "HIGH"
	} else if d.CveScore >= 4 && d.CveScore <= 7 {
		d.Sensibility = "MEDIUM"
	} else if d.CveScore < 4 {
		d.Sensibility = "LOW"
	}
	d.CveList = utils.RemoveDuplicates(d.CveList)
}

func (d *Dell) PrintInfo() string { return model.Category.Printer() + " | Dell" }

func (d *Dell) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         d.Category,
		DeviceName:       d.DeviceName,
		Version:          d.Version,
		CveList:          d.CveList,
		Sensibility:      d.Sensibility,
		CveScore:         d.CveScore,
		ExtraInformation: d.ExtraInfo,
	}
}
