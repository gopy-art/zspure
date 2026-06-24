package unifi

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

type Unifi struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (u *Unifi) SetCategory(category ...string) {
	u.Category = model.Category.Camera()
}

func (u *Unifi) SetDeviceName(device ...string) {
	u.DeviceName = "Unifi"
}

func (a *Unifi) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.response.body": "<title>UniFi Video</title>"},
		{"result.response.body": "<main-view ui-view></main-view>"},
	}
}

func (u *Unifi) Filters(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	if val, ok := banner["response"].(map[string]interface{})["body"]; ok {
		if (strings.Contains(val.(string), "<title>UniFi Video</title>") ||
			strings.Contains(val.(string), "<main-view ui-view></main-view>")) &&
			!strings.Contains(val.(string), "0<!DOCTYPE html>") &&
			!strings.Contains(val.(string), "<p hidden>") {
			return true
		}
	}
	return false
}

func (u *Unifi) DeviceScan(banner map[string]interface{}) bool {
	u.ExtraInformation.NewExtraInfo()
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if server, sok := val.(map[string]interface{})["server"].([]any); sok {
			u.ExtraInformation.SetExtraInfo("server", server[0].(string))
		}
	}
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if pl, pok := val.(map[string]interface{})["x_powered_by"].([]any); pok {
			u.ExtraInformation.SetExtraInfo("programming_language", pl[0].(string))
		}
	}
	return false
}

func (u *Unifi) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{"cve.descriptions.value": fmt.Sprintf("%s %s", u.DeviceName, u.Version)}))
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
			strings.ToLower(strings.ReplaceAll(fmt.Sprintf("%v", u.DeviceName), " ", "%20")))
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
		u.CveList = append(u.CveList, v.CVEID)
		totalScore += v.BaseScore
	}

	u.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if u.CveScore > 7 {
		u.Sensibility = "HIGH"
	} else if u.CveScore >= 4 && u.CveScore <= 7 {
		u.Sensibility = "MEDIUM"
	} else if u.CveScore < 4 {
		u.Sensibility = "LOW"
	}
	u.CveList = utils.RemoveDuplicates(u.CveList)
}

func (u *Unifi) PrintInfo() string { return model.Category.Camera() + " | Unifi" }

func (u *Unifi) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         u.Category,
		DeviceName:       u.DeviceName,
		Version:          u.Version,
		CveList:          u.CveList,
		Sensibility:      u.Sensibility,
		CveScore:         u.CveScore,
		ExtraInformation: u.ExtraInformation,
	}
}
