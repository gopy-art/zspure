package xerox

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

	"github.com/PuerkitoBio/goquery"
)

type Xerox struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (x *Xerox) SetCategory(category ...string) {
	x.Category = model.Category.Printer()
}

func (x *Xerox) SetDeviceName(device ...string) {
	x.DeviceName = "Xerox"
}

func (x *Xerox) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.response.body": "<title>Xerox"},
	}
}

func (x *Xerox) Filters(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	if val, ok := banner["response"].(map[string]interface{})["body"]; ok {
		if strings.Contains(val.(string), "0<!DOCTYPE html>") &&
			strings.Contains(val.(string), "<p hidden>") {
			return false
		}

		doc, err := goquery.NewDocumentFromReader(strings.NewReader(val.(string)))
		if err != nil {
			return false
		}
		if strings.Contains(doc.Find("title").Text(), "Xerox") && 
			strings.Contains(doc.Find("title").Text(), "Phaser") {
			return true
		}
	}
	return false
}

func (x *Xerox) DeviceScan(banner map[string]interface{}) bool {
	x.ExtraInformation.NewExtraInfo()
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if server, sok := val.(map[string]interface{})["server"].([]any); sok {
			x.ExtraInformation.SetExtraInfo("server", server[0].(string))
		}
	}
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if pl, pok := val.(map[string]interface{})["x_powered_by"].([]any); pok {
			x.ExtraInformation.SetExtraInfo("programming_language", pl[0].(string))
		}
	}

	if val, ok := banner["response"].(map[string]interface{})["body"].(string); ok {
		doc, err := goquery.NewDocumentFromReader(strings.NewReader(val))
		if err != nil {
			return false
		}

		version := regexp.MustCompile(`Phaser\s+(\d+)`)
		matches := version.FindStringSubmatch(strings.TrimSpace(doc.Find("title").Text()))
		if len(matches) > 1 {
			x.Version = matches[1]
		}
	}

	return false
}

func (x *Xerox) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{"cve.descriptions.value": fmt.Sprintf("%s %s", x.DeviceName, x.Version)}))
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
		url := fmt.Sprintf(model.CVE.MainResource(), "xerox%20"+x.Version)
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
		x.CveList = append(x.CveList, v.CVEID)
		totalScore += v.BaseScore
	}

	x.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if x.CveScore > 7 {
		x.Sensibility = "HIGH"
	} else if x.CveScore >= 4 && x.CveScore <= 7 {
		x.Sensibility = "MEDIUM"
	} else if x.CveScore < 4 {
		x.Sensibility = "LOW"
	}
	x.CveList = utils.RemoveDuplicates(x.CveList)
}

func (x *Xerox) PrintInfo() string { return model.Category.Printer() + " | Xerox" }

func (x *Xerox) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         x.Category,
		DeviceName:       x.DeviceName,
		Version:          x.Version,
		CveList:          x.CveList,
		Sensibility:      x.Sensibility,
		CveScore:         x.CveScore,
		ExtraInformation: x.ExtraInformation,
	}
}
