package moxaoncell

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

type MoxaOnCell struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (m *MoxaOnCell) SetCategory(category ...string) {
	m.Category = model.Category.Router()
}

func (m *MoxaOnCell) SetDeviceName(device ...string) {
	m.DeviceName = "Moxa OnCell"
}

func (a *MoxaOnCell) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.response.body": "<TITLE>OnCell G3110-HSPA Web Console</TITLE>"},
		{"result.response.body": "<TITLE>OnCell G3110-HSPA Series Web Console</TITLE>"},
	}
}

func (m *MoxaOnCell) Filters(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	if val, ok := banner["response"].(map[string]interface{})["body"]; ok {
		if (strings.Contains(val.(string), "<TITLE>OnCell G3110-HSPA Web Console</TITLE>") ||
			strings.Contains(val.(string), "<TITLE>OnCell G3110-HSPA Series Web Console</TITLE>>")) &&
			!strings.Contains(val.(string), "0<!DOCTYPE html>") &&
			!strings.Contains(val.(string), "<p hidden>") {
			return true
		}
	}
	return false
}

func (m *MoxaOnCell) DeviceScan(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	m.ExtraInformation.NewExtraInfo()
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if server, sok := val.(map[string]interface{})["server"].([]any); sok {
			m.ExtraInformation.SetExtraInfo("server", server[0].(string))
		}
	}
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if pl, pok := val.(map[string]interface{})["x_powered_by"].([]any); pok {
			m.ExtraInformation.SetExtraInfo("programming_language", pl[0].(string))
		}
	}
	if val, ok := banner["response"].(map[string]interface{})["body"]; ok {
		doc, err := goquery.NewDocumentFromReader(strings.NewReader(val.(string)))
		if err != nil {
			return false
		}

		// Find the `TAG:title` and get its text it will include version
		text := doc.Find("title").Text()
		words := strings.Fields(text)

		if len(words) >= 4 {
			m.Version = words[1]
			return true
		}
	}
	return false
}

func (m *MoxaOnCell) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{"cve.descriptions.value": fmt.Sprintf("%s %s", m.DeviceName, m.Version)}))
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
			strings.ToLower(strings.ReplaceAll(fmt.Sprintf("%v %v", m.DeviceName, m.Version), " ", "%20")))
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
		m.CveList = append(m.CveList, v.CVEID)
		totalScore += v.BaseScore
	}

	m.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if m.CveScore > 7 {
		m.Sensibility = "HIGH"
	} else if m.CveScore >= 4 && m.CveScore <= 7 {
		m.Sensibility = "MEDIUM"
	} else if m.CveScore < 4 {
		m.Sensibility = "LOW"
	}
	m.CveList = utils.RemoveDuplicates(m.CveList)
}

func (m *MoxaOnCell) PrintInfo() string { return model.Category.Router() + " | Moxa OnCell" }

func (m *MoxaOnCell) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         m.Category,
		DeviceName:       m.DeviceName,
		Version:          m.Version,
		CveList:          m.CveList,
		Sensibility:      m.Sensibility,
		CveScore:         m.CveScore,
		ExtraInformation: m.ExtraInformation,
	}
}
