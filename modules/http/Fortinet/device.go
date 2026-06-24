/*

THE DATA WOULD BE LIKE THIS :
	0
	Fortinet:
		Device: FortiGate-601E
		Model: FG6H1E
		Serial Number: FG6H1ETB21907491

*/

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

type FortinetDevice struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (f *FortinetDevice) SetCategory(category ...string) {
	f.Category = model.Category.Firewall()
}

func (f *FortinetDevice) SetDeviceName(device ...string) {
	f.DeviceName = ""
}

func (a *FortinetDevice) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.response.body": "Fortinet:"},
		{"result.response.body": "Device:"},
		{"result.response.body": "Serial Number:"},
	}
}

func (f *FortinetDevice) Filters(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	if val, ok := banner["response"].(map[string]interface{})["body"]; ok {
		if strings.Contains(val.(string), "Fortinet:") &&
			strings.Contains(val.(string), "Device:") &&
			strings.Contains(val.(string), "Serial Number:") &&
			!strings.Contains(val.(string), "0<!DOCTYPE html>") &&
			!strings.Contains(val.(string), "<p hidden>") {
			return true
		}
	}
	return false
}

func (f *FortinetDevice) DeviceScan(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
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
	if val, ok := banner["response"].(map[string]interface{})["body"]; ok {
		if strings.Contains(val.(string), "Device") {
			f.DeviceName = strings.Trim(strings.Split(val.(string), " ")[3], "\n")
		}
		if strings.Contains(val.(string), "Model") {
			f.Version = strings.Trim(strings.Split(val.(string), " ")[6], "\n")
		}
	}
	return false
}

func (f *FortinetDevice) CveScan(els *handler.Elastic) {
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
		url := fmt.Sprintf(model.CVE.MainResource(), 
			strings.ReplaceAll(fmt.Sprintf("%s %v", f.DeviceName, f.Version), " ", "%20"))
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

func (f *FortinetDevice) PrintInfo() string { return model.Category.Firewall() + " | Fortinet Device" }

func (f *FortinetDevice) Result() model.ModuleStructure {
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
