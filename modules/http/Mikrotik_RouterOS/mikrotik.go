package Mikrotik

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

type Mikrotik struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (m *Mikrotik) SetCategory(category ...string) {
	m.Category = model.Category.Router()
}

func (m *Mikrotik) SetDeviceName(device ...string) {
	m.DeviceName = "MikroTik RouterOs"
}

func (a *Mikrotik) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.response.body": "<title>RouterOS router configuration page</title>"},
		{"result.response.body": "<h1>RouterOS"},
		{"result.response.body": "<a href=\"http://mikrotik.com\"><img src=\"mikrotik_logo.png\" style=\"float: right;\" /></a>"},
	}
}

func (m *Mikrotik) Filters(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	if val, ok := banner["response"].(map[string]interface{})["body"]; ok {
		if strings.Contains(val.(string), "<title>RouterOS router configuration page</title>") &&
			strings.Contains(val.(string), "<h1>RouterOS") &&
			(strings.Contains(val.(string), "<a href=\"http://mikrotik.com\"><img src=\"mikrotik_logo.png\" style=\"float: right;\" /></a>") ||
				strings.Contains(val.(string), "<a href=\"http://mikrotik.com\"><img src=\"mikrotik_logo.png\" style=\"float: right;\"></a>")) &&
			!strings.Contains(val.(string), "0<!DOCTYPE html>") &&
			!strings.Contains(val.(string), "<p hidden>") {
			return true
		}
	}
	return false
}

func (m *Mikrotik) DeviceScan(banner map[string]interface{}) bool {
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

		// Find the <h1> tag and get its text it will include => RouterOS vX.X.X
		text := doc.Find("h1").Text()
		words := strings.Fields(text)

		if len(words) >= 2 {
			m.Version = words[1]
			return true
		}
	}
	return false
}

func (m *Mikrotik) CveScan(els *handler.Elastic) {
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

func (m *Mikrotik) PrintInfo() string { return model.Category.Router() + " | MikroTik RouterOs" }

func (m *Mikrotik) Result() model.ModuleStructure {
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
