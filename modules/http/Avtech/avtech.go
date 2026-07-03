package avtech

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"zspure/config"
	"zspure/config/cmd"
	"zspure/handler"
	"zspure/modules/model"
	"zspure/utils"
)

type Avtech struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (a *Avtech) SetCategory(category ...string) {
	a.Category = model.Category.Monitoring()
}

func (a *Avtech) SetDeviceName(device ...string) {
	a.DeviceName = "AVTECH Room Alert"
}

func (a *Avtech) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.response.body": "<title>AVTECH Software, Inc."},
	}
}

func (a *Avtech) Filters(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	if val, ok := banner["response"].(map[string]interface{})["body"].(string); ok {
		if strings.Contains(val, "0<!DOCTYPE html>") &&
			strings.Contains(val, "<p hidden>") {
			return false
		}
		if strings.Contains(val, "<title>AVTECH Software, Inc") && strings.Contains(val, "Room Alert") {
			return true
		}
	}
	return false
}

func (a *Avtech) DeviceScan(banner map[string]interface{}) bool {
	a.ExtraInformation.NewExtraInfo()
	if val, ok := banner["response"].(map[string]interface{})["body"].(string); ok {
		re := regexp.MustCompile(`Room Alert\s+([A-Za-z0-9]+)`)
		matches := re.FindStringSubmatch(val)
		if len(matches) > 1 {
			a.ExtraInformation.SetExtraInfo("product", "Room Alert "+matches[1])
		}
	}
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if server, sok := val.(map[string]interface{})["server"].([]any); sok {
			a.ExtraInformation.SetExtraInfo("server", server[0].(string))
		}
	}
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if pl, pok := val.(map[string]interface{})["x_powered_by"].([]any); pok {
			a.ExtraInformation.SetExtraInfo("programming_language", pl[0].(string))
		}
	}
	return false
}

func (a *Avtech) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": a.DeviceName,
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
		url := fmt.Sprintf(model.CVE.MainResource(), "avtech"+"%20"+"room"+"%20"+"alert")
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
		a.CveList = append(a.CveList, vl.CVEID)
		totalScore += vl.BaseScore
	}
	a.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if a.CveScore > 7 {
		a.Sensibility = "HIGH"
	} else if a.CveScore >= 4 && a.CveScore <= 7 {
		a.Sensibility = "MEDIUM"
	} else if a.CveScore < 4 {
		a.Sensibility = "LOW"
	}
	a.CveList = utils.RemoveDuplicates(a.CveList)
}

func (a *Avtech) PrintInfo() string { return model.Category.Monitoring() + " | Avtech Room Alert" }

func (a *Avtech) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         a.Category,
		DeviceName:       a.DeviceName,
		Version:          a.Version,
		CveList:          a.CveList,
		Sensibility:      a.Sensibility,
		CveScore:         a.CveScore,
		ExtraInformation: a.ExtraInformation,
	}
}
