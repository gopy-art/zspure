package checkpoint

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

type CheckPointPanel struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (c *CheckPointPanel) SetCategory(category ...string) {
	c.Category = model.Category.Firewall()
}

func (c *CheckPointPanel) SetDeviceName(device ...string) {
	c.DeviceName = "Check Point"
}

func (a *CheckPointPanel) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.response.body": "CHECK POINT SECURITY APPLIANCE"},
		{"result.response.body": "QUANTUM SPARK SECURITY APPLIANCE"},
	}
}

func (c *CheckPointPanel) Filters(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	if val, ok := banner["response"].(map[string]interface{})["body"]; ok {
		if (strings.Contains(strings.ToUpper(val.(string)), "QUANTUM SPARK SECURITY APPLIANCE") ||
			strings.Contains(strings.ToUpper(val.(string)), "CHECK POINT SECURITY APPLIANCE")) &&
			!strings.Contains(val.(string), "0<!DOCTYPE html>") &&
			!strings.Contains(val.(string), "<p hidden>") {
			return true
		}
	}
	return false
}

func (c *CheckPointPanel) DeviceScan(banner map[string]interface{}) bool {
	c.ExtraInformation.NewExtraInfo()
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if server, sok := val.(map[string]interface{})["server"].([]any); sok {
			c.ExtraInformation.SetExtraInfo("server", server[0].(string))
		}
	}
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if pl, pok := val.(map[string]interface{})["x_powered_by"].([]any); pok {
			c.ExtraInformation.SetExtraInfo("programming_language", pl[0].(string))
		}
	}
	return false
}

func (c *CheckPointPanel) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{"cve.descriptions.value": "check point"}))
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
		url := fmt.Sprintf(model.CVE.MainResource(), "check point")
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
		c.CveList = append(c.CveList, v.CVEID)
		totalScore += v.BaseScore
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

func (c *CheckPointPanel) PrintInfo() string {
	return model.Category.Firewall() + " | Check Point Panel"
}

func (c *CheckPointPanel) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         c.Category,
		DeviceName:       c.DeviceName,
		Version:          c.Version,
		CveList:          c.CveList,
		Sensibility:      c.Sensibility,
		CveScore:         c.CveScore,
		ExtraInformation: c.ExtraInformation,
	}
}
