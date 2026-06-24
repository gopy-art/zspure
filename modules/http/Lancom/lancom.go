package lancom

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

type Lancom struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (l *Lancom) SetCategory(category ...string) {
	l.Category = model.Category.Router()
}

func (l *Lancom) SetDeviceName(device ...string) {
	l.DeviceName = "Lancom"
}

func (a *Lancom) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.response.body": "<title>Lancom"},
		{"result.response.body": "Login</title>"},
		{"result.response.body": "<p class=\"headerp\">LANCOM"},
		{"result.response.body": "(over ISDN)</p>"},
	}
}

func (l *Lancom) Filters(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	if val, ok := banner["response"].(map[string]interface{})["body"]; ok {
		if ((strings.Contains(val.(string), "<title>Lancom") && strings.Contains(val.(string), "Login</title>")) ||
			(strings.Contains(val.(string), "<p class=\"headerp\">LANCOM") && strings.Contains(val.(string), "(over ISDN)</p>"))) &&
			!strings.Contains(val.(string), "0<!DOCTYPE html>") &&
			!strings.Contains(val.(string), "<p hidden>") {
			return true
		}
	}
	return false
}

func (l *Lancom) DeviceScan(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	l.ExtraInformation.NewExtraInfo()
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if server, sok := val.(map[string]interface{})["server"].([]any); sok {
			l.ExtraInformation.SetExtraInfo("server", server[0].(string))
		}
	}
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if pl, pok := val.(map[string]interface{})["x_powered_by"].([]any); pok {
			l.ExtraInformation.SetExtraInfo("programming_language", pl[0].(string))
		}
	}
	if val, ok := banner["response"].(map[string]interface{})["body"]; ok {
		doc, err := goquery.NewDocumentFromReader(strings.NewReader(val.(string)))
		if err != nil {
			return false
		}

		// Find the `TAG:p CLASS:headerp` tag and get its text it will include version
		text := doc.Find("p.headerp").Text()
		words := strings.Fields(text)

		if len(words) >= 3 {
			l.Version = words[1]
			return true
		}
	}
	return false
}

func (l *Lancom) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{"cve.descriptions.value": fmt.Sprintf("%s %s", l.DeviceName, l.Version)}))
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
		url := fmt.Sprintf(model.CVE.MainResource(), "lancom%20"+l.Version)
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
		l.CveList = append(l.CveList, v.CVEID)
		totalScore += v.BaseScore
	}

	l.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if l.CveScore > 7 {
		l.Sensibility = "HIGH"
	} else if l.CveScore >= 4 && l.CveScore <= 7 {
		l.Sensibility = "MEDIUM"
	} else if l.CveScore < 4 {
		l.Sensibility = "LOW"
	}
	l.CveList = utils.RemoveDuplicates(l.CveList)
}

func (l *Lancom) PrintInfo() string { return model.Category.Router() + " | Lancom" }

func (l *Lancom) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         l.Category,
		DeviceName:       l.DeviceName,
		Version:          l.Version,
		CveList:          l.CveList,
		Sensibility:      l.Sensibility,
		CveScore:         l.CveScore,
		ExtraInformation: l.ExtraInformation,
	}
}
