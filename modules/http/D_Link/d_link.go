package dlink

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

type DLink struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (d *DLink) SetCategory(category ...string) {
	d.Category = model.Category.Router()
}

func (d *DLink) SetDeviceName(device ...string) {
	d.DeviceName = "D-Link"
}

func (a *DLink) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.response.body": "D-LINK"},
		{"result.response.body": "Firmware Version"},
	}
}

func (d *DLink) Filters(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	if val, ok := banner["response"].(map[string]interface{})["body"]; ok {
		if (strings.Contains(val.(string), "D-LINK") ||
			(strings.Contains(val.(string), "D-LINK") && strings.Contains(val.(string), "Firmware Version"))) &&
			!strings.Contains(val.(string), "0<!DOCTYPE html>") &&
			!strings.Contains(val.(string), "<p hidden>") {
			return true
		}
	}
	return false
}

func (d *DLink) DeviceScan(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	d.ExtraInformation.NewExtraInfo()
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if server, sok := val.(map[string]interface{})["server"].([]any); sok {
			d.ExtraInformation.SetExtraInfo("server", server[0].(string))
		}
	}
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if pl, pok := val.(map[string]interface{})["x_powered_by"].([]any); pok {
			d.ExtraInformation.SetExtraInfo("programming_language", pl[0].(string))
		}
	}
	if val, ok := banner["response"].(map[string]interface{})["body"]; ok {
		doc, err := goquery.NewDocumentFromReader(strings.NewReader(val.(string)))
		if err != nil {
			return false
		}

		if doc.Find("span.product").Text() != "" {
			// Find the `CLASS:product` tag and get its text it will include version
			text := doc.Find("span.product").Text()
			words := strings.Fields(text)

			if len(words) >= 4 {
				d.Version = words[3]
				return true
			}
		} else if doc.Find("div.version").Length() > 0 && doc.Find("div.model").Length() > 0 {
			// Find the `TAG:div CLASS:product` and `TAG:div CLASS:model` and get its text it will include version
			version := doc.Find("div.version").Text()
			vmodel := doc.Find("div.model").Text()

			if version != "" && vmodel != "" {
				d.Version = fmt.Sprintf("%s %s", vmodel, version)
				return true
			}
		}
	}
	return false
}

func (d *DLink) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{"cve.descriptions.value": fmt.Sprintf("%s %s", d.DeviceName, d.Version)}))
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
			strings.ReplaceAll("d-link%20"+d.Version, " ", "%20"))
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

func (d *DLink) PrintInfo() string { return model.Category.Router() + " | D-Link" }

func (d *DLink) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         d.Category,
		DeviceName:       d.DeviceName,
		Version:          d.Version,
		CveList:          d.CveList,
		Sensibility:      d.Sensibility,
		CveScore:         d.CveScore,
		ExtraInformation: d.ExtraInformation,
	}
}
