package exporter

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

type NodeExporter struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (e *NodeExporter) SetCategory(category ...string) {
	e.Category = model.Category.Monitoring()
}

func (e *NodeExporter) SetDeviceName(device ...string) {
	e.DeviceName = ""
}

func (a *NodeExporter) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.response.body": "Exporter</title>"},
		{"result.response.body": "<a href=\"/metrics\">Metrics</a>"},
	}
}

func (e *NodeExporter) Filters(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	if val, ok := banner["response"].(map[string]interface{})["body"]; ok {
		if (strings.Contains(strings.ToUpper(val.(string)), strings.ToUpper("Exporter</title>")) ||
			strings.Contains(val.(string), "<a href=\"/metrics\">Metrics</a>")) &&
			!strings.Contains(val.(string), "0<!DOCTYPE html>") &&
			!strings.Contains(val.(string), "<p hidden>") {
			return true
		}
	}
	return false
}

func (e *NodeExporter) DeviceScan(banner map[string]interface{}) bool {
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
		text := doc.Find("title").Text()
		e.DeviceName = text

		// Find all divs whose text contains "ersion: (version="
		doc.Find("div").Each(func(i int, s *goquery.Selection) {
			text := strings.TrimSpace(s.Text())
			if strings.Contains(strings.ToLower(text), "version: (version=") {
				e.Version = strings.Split(strings.Split(text, ",")[0], "=")[1]
			}
		})
	}
	return false
}

func (e *NodeExporter) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{"cve.descriptions.value": e.DeviceName}))
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
			strings.ReplaceAll(fmt.Sprintf("%s %v", e.DeviceName, e.Version), " ", "%20"))
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

func (e *NodeExporter) PrintInfo() string { return model.Category.Monitoring() + " | Exporter" }

func (e *NodeExporter) Result() model.ModuleStructure {
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
