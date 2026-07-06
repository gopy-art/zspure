package axis

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

type Axis struct {
	Category    string                `json:"dvs_category"`
	DeviceName  string                `json:"device_name"`
	Version     string                `json:"version"`
	CveList     []string              `json:"cves"`
	Sensibility string                `json:"base_severity"`
	CveScore    float64               `json:"cve_score"`
	ExtraInfo   model.ModuleExtraInfo `json:"dvs_extra"`
}

func (a *Axis) SetCategory(category ...string) {
	a.Category = model.Category.Camera()
}

func (a *Axis) SetDeviceName(device ...string) {
	a.DeviceName = "Axis Camera"
}

func (a *Axis) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.response.body": "AXIS 2120 Network Camera"},
		{"result.response.body": "AXIS 2100 Network Camera"},
		{"result.response.body": "Live view / - AXIS 205 Network Camera"},
	}
}

func (a *Axis) Filters(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	if val, ok := banner["response"].(map[string]interface{})["body"].(string); ok {
		if (strings.Contains(val, "AXIS") && 
			strings.Contains(val, "Network Camera")) &&
			!strings.Contains(val, "0<!DOCTYPE html>") &&
			!strings.Contains(val, "<p hidden>") {
			return true
		}
	}
	return false
}

func (a *Axis) DeviceScan(banner map[string]interface{}) bool {
	a.ExtraInfo.NewExtraInfo()
	if val, ok := banner["response"].(map[string]interface{})["body"].(string); ok {
		if strings.Contains(val, "AXIS 2120 Network Camera") {
			a.ExtraInfo.SetExtraInfo("product", "2120 Network Camera")
		}
		if strings.Contains(val, "AXIS 2100 Network Camera") {
			a.ExtraInfo.SetExtraInfo("product", "2100 Network Camera")
		}
		if strings.Contains(val, "Live view / - AXIS 205 Network Camera") {
			a.ExtraInfo.SetExtraInfo("product", "205 Network Camera")
		}
	}
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if server, sok := val.(map[string]interface{})["server"].([]any); sok {
			a.ExtraInfo.SetExtraInfo("server", server[0].(string))
		}
	}
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if pl, pok := val.(map[string]interface{})["x_powered_by"].([]any); pok {
			a.ExtraInfo.SetExtraInfo("programming_language", pl[0].(string))
		}
	}
	return false
}

func (a *Axis) CveScan(els *handler.Elastic) {
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
		url := fmt.Sprintf(model.CVE.MainResource(), "axis")
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

func (a *Axis) PrintInfo() string { return model.Category.Camera() + " | Axis Camera" }

func (a *Axis) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         a.Category,
		DeviceName:       a.DeviceName,
		Version:          a.Version,
		CveList:          a.CveList,
		Sensibility:      a.Sensibility,
		CveScore:         a.CveScore,
		ExtraInformation: a.ExtraInfo,
	}
}
