package eltex

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

type Eltex struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (e *Eltex) SetCategory(category ...string) {
	e.Category = model.Category.Router()
}

func (e *Eltex) SetDeviceName(device ...string) {
	e.DeviceName = "Eltex"
}

func (a *Eltex) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.response.body": "<title>Eltex - NTU-RG-1402G-W</title>"},
		{"result.response.body": "background: #2f3133 url(\"logo.png\") no-repeat left center"},
	}
}

func (e *Eltex) Filters(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	if val, ok := banner["response"].(map[string]interface{})["body"]; ok {
		if (strings.Contains(val.(string), "<title>Eltex - NTU-RG-1402G-W</title>") ||
			strings.Contains(val.(string), "background: #2f3133 url(\"logo.png\") no-repeat left center")) &&
			!strings.Contains(val.(string), "0<!DOCTYPE html>") &&
			!strings.Contains(val.(string), "<p hidden>") {
			return true
		}
	}
	return false
}

func (e *Eltex) DeviceScan(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	e.ExtraInformation.NewExtraInfo()
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if server, sok := val.(map[string]interface{})["server"].([]any); sok {
			e.ExtraInformation.SetExtraInfo("server", server[0].(string))
		}
	}
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if pl, pok := val.(map[string]interface{})["x_powered_by"].([]any); pok {
			e.ExtraInformation.SetExtraInfo("programming_language", pl[0].(string))
		}
	}
	if val, ok := banner["response"].(map[string]interface{})["body"]; ok {
		doc, err := goquery.NewDocumentFromReader(strings.NewReader(val.(string)))
		if err != nil {
			return false
		}

		// Find the `TAG:b` and get its text it will include version
		text := doc.Find("b").Text()

		if text != "" {
			e.Version = text
			return true
		}
	}
	return false
}

func (e *Eltex) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{"cve.descriptions.value": fmt.Sprintf("%s %s", e.DeviceName, e.Version)}))
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
		url := fmt.Sprintf(model.CVE.MainResource(), "eltex%20"+strings.ToLower(e.Version))
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
		e.CveList = append(e.CveList, v.CVEID)
		totalScore += v.BaseScore
	}

	e.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if e.CveScore > 7 {
		e.Sensibility = "HIGH"
	} else if e.CveScore >= 4 && e.CveScore <= 7 {
		e.Sensibility = "MEDIUM"
	} else if e.CveScore < 4 {
		e.Sensibility = "LOW"
	}
	e.CveList = utils.RemoveDuplicates(e.CveList)
}

func (e *Eltex) PrintInfo() string { return model.Category.Router() + " | Eltex" }

func (e *Eltex) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         e.Category,
		DeviceName:       e.DeviceName,
		Version:          e.Version,
		CveList:          e.CveList,
		Sensibility:      e.Sensibility,
		CveScore:         e.CveScore,
		ExtraInformation: e.ExtraInformation,
	}
}
