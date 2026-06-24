package ciscowap121

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

type CiscoWAP121 struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (c *CiscoWAP121) SetCategory(category ...string) {
	c.Category = model.Category.AccessPoint()
}

func (c *CiscoWAP121) SetDeviceName(device ...string) {
	c.DeviceName = "Cisco WAP121"
}

func (a *CiscoWAP121) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.response.body": "cisco"},
		{"result.response.body": "<span class=\"about-product-title\">Wireless Access Point</span>"},
		{"result.response.body": "/open_auth/cisco_logo_about.png"},
		{"result.response.body": "<title>WAP121 - Wireless"},
	}
}

func (c *CiscoWAP121) Filters(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	if val, ok := banner["response"].(map[string]interface{})["body"]; ok {
		if strings.Contains(val.(string), "cisco") &&
			strings.Contains(val.(string), "<span class=\"about-product-title\">Wireless Access Point</span>") &&
			strings.Contains(val.(string), "/open_auth/cisco_logo_about.png") &&
			strings.Contains(val.(string), "<title>WAP121 - Wireless") {
			return true
		}
	}
	return false
}

func (c *CiscoWAP121) DeviceScan(banner map[string]interface{}) bool {
	// TODO : THE VERSION IS NOT SPECIFIED IN THE HTML BODY
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

func (c *CiscoWAP121) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{"cve.descriptions.value": fmt.Sprintf("%s %s", c.DeviceName, c.Version)}))
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
		url := fmt.Sprintf(model.CVE.MainResource(), "cisco wap121")
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

func (c *CiscoWAP121) PrintInfo() string {
	return model.Category.AccessPoint() + " | Cisco WAP121 - Wireless"
}

func (c *CiscoWAP121) Result() model.ModuleStructure {
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
