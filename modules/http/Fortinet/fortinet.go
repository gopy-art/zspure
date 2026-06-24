package fortinet

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

type Fortinet struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (f *Fortinet) SetCategory(category ...string) {
	f.Category = model.Category.Firewall()
}

func (f *Fortinet) SetDeviceName(device ...string) {
	f.DeviceName = "Fortinet Login"
}

func (a *Fortinet) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.response.body": "<f-icon class=\"ftnt-fortinet-grid icon-xl\"></f-icon>"},
		{"result.response.body": "<title>FortiGate</title>"},
		{"result.response.body": "<fos-root></fos-root>"},
		{"result.response.body": "top.location=\"/login\";"},
	}
}

func (f *Fortinet) Filters(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	if val, ok := banner["response"].(map[string]interface{})["body"]; ok {
		if (strings.Contains(val.(string), "<f-icon class=\"ftnt-fortinet-grid icon-xl\"></f-icon>") ||
			(strings.Contains(val.(string), "<title>FortiGate</title>") && strings.Contains(val.(string), "<fos-root></fos-root>")) ||
			strings.Contains(val.(string), "top.location=\"/login\";")) &&
			!strings.Contains(val.(string), "0<!DOCTYPE html>") &&
			!strings.Contains(val.(string), "<p hidden>") {
			return true
		}
	}
	return false
}

func (f *Fortinet) DeviceScan(banner map[string]interface{}) bool {
	f.ExtraInformation.NewExtraInfo()
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if server, sok := val.(map[string]interface{})["server"].([]any); sok {
			f.ExtraInformation.SetExtraInfo("server", server[0].(string))
		}
	}
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if pl, pok := val.(map[string]interface{})["x_powered_by"].([]any); pok {
			f.ExtraInformation.SetExtraInfo("programming_language", pl[0].(string))
		}
	}
	return false
}

func (f *Fortinet) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
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
	} else if config.FIND_CVE {
		url := fmt.Sprintf(model.CVE.MainResource(), "fortinet")
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
		Category:         f.Category,
		DeviceName:       f.DeviceName,
		Version:          f.Version,
		CveList:          f.CveList,
		Sensibility:      f.Sensibility,
		CveScore:         f.CveScore,
		ExtraInformation: f.ExtraInformation,
	}
}
