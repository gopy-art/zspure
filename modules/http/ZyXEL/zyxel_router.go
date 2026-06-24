package zyxel

import (
	"fmt"
	"strconv"
	"strings"
	"zspure/config"
	"zspure/config/cmd"
	"zspure/handler"
	"zspure/modules/model"
	"zspure/utils"

	"github.com/PuerkitoBio/goquery"
)

type ZyXELRouter struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (z *ZyXELRouter) SetCategory(category ...string) {
	z.Category = model.Category.Router()
}

func (z *ZyXELRouter) SetDeviceName(device ...string) {
	z.DeviceName = ""
}

func (a *ZyXELRouter) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.response.body": "zyxel"},
		{"result.response.body": "ZyXEL"},
		{"result.response.body": "<title>.::Welcome to the Web-Based Configurator::.</title>"},
		{"result.response.body": "<title>.::Welcome to ZyXEL"},
	}
}

func (z *ZyXELRouter) Filters(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	if val, ok := banner["response"].(map[string]interface{})["body"]; ok {
		if (strings.Contains(val.(string), "zyxel") || strings.Contains(val.(string), "ZyXEL")) &&
			(strings.Contains(val.(string), "<title>.::Welcome to the Web-Based Configurator::.</title>") || strings.Contains(val.(string), "<title>.::Welcome to ZyXEL")) &&
			!strings.Contains(val.(string), "0<!DOCTYPE html>") &&
			!strings.Contains(val.(string), "<p hidden>") {
			return true
		}
	}
	return false
}

func (z *ZyXELRouter) DeviceScan(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	z.ExtraInformation.NewExtraInfo()
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if server, sok := val.(map[string]interface{})["server"].([]any); sok {
			z.ExtraInformation.SetExtraInfo("server", server[0].(string))
		}
	}
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if pl, pok := val.(map[string]interface{})["x_powered_by"].([]any); pok {
			z.ExtraInformation.SetExtraInfo("programming_language", pl[0].(string))
		}
	}
	if val, ok := banner["response"].(map[string]interface{})["body"]; ok {
		z.DeviceName = "ZyXEL Gateway"
		if strings.Contains(val.(string), "<title>.::Welcome to ZyXEL") {
			doc, err := goquery.NewDocumentFromReader(strings.NewReader(val.(string)))
			if err != nil {
				return false
			}

			// Find the `TAG:div #model` and get its text it will include device name with version
			text := doc.Find("title").Text()
			words := strings.Fields(text)

			if text != "" {
				z.Version = strings.Split(words[3], "::.")[0]
				return true
			}
		}
	}
	return false
}

func (z *ZyXELRouter) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{"cve.descriptions.value": fmt.Sprintf("ZyXEL %s", z.Version)}))
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
			strings.ToLower(strings.ReplaceAll(fmt.Sprintf("%v %v", "ZyXEL", z.Version), " ", "%20")))
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
		z.CveList = append(z.CveList, v.CVEID)
		totalScore += v.BaseScore
	}

	z.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if z.CveScore > 7 {
		z.Sensibility = "HIGH"
	} else if z.CveScore >= 4 && z.CveScore <= 7 {
		z.Sensibility = "MEDIUM"
	} else if z.CveScore < 4 {
		z.Sensibility = "LOW"
	}
	z.CveList = utils.RemoveDuplicates(z.CveList)
}

func (z *ZyXELRouter) PrintInfo() string { return model.Category.Router() + " | ZyXEL Gateway" }

func (z *ZyXELRouter) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         z.Category,
		DeviceName:       z.DeviceName,
		Version:          z.Version,
		CveList:          z.CveList,
		Sensibility:      z.Sensibility,
		CveScore:         z.CveScore,
		ExtraInformation: z.ExtraInformation,
	}
}
