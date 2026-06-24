package gargoyle

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

type Gargoyle struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (g *Gargoyle) SetCategory(category ...string) {
	g.Category = model.Category.Router()
}

func (g *Gargoyle) SetDeviceName(device ...string) {
	g.DeviceName = "Gargoyle"
}

func (a *Gargoyle) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.response.body": "<title>Gargoyle Router Management Utility</title>"},
		{"result.response.body": "<span id=\"garg_title\">Gargoyle</span>"},
		{"result.response.body": "<span id=\"garg_host\">Device Name:"},
	}
}

func (g *Gargoyle) Filters(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	if val, ok := banner["response"].(map[string]interface{})["body"]; ok {
		if (strings.Contains(val.(string), "<title>Gargoyle Router Management Utility</title>") ||
			strings.Contains(val.(string), "<span id=\"garg_title\">Gargoyle</span>") &&
				strings.Contains(val.(string), "<span id=\"garg_host\">Device Name:")) &&
			!strings.Contains(val.(string), "0<!DOCTYPE html>") &&
			!strings.Contains(val.(string), "<p hidden>") {
			return true
		}
	}
	return false
}

func (g *Gargoyle) DeviceScan(banner map[string]interface{}) bool {
	g.ExtraInformation.NewExtraInfo()
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if server, sok := val.(map[string]interface{})["server"].([]any); sok {
			g.ExtraInformation.SetExtraInfo("server", server[0].(string))
		}
	}
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if pl, pok := val.(map[string]interface{})["x_powered_by"].([]any); pok {
			g.ExtraInformation.SetExtraInfo("programming_language", pl[0].(string))
		}
	}
	return false
}

func (g *Gargoyle) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{"cve.descriptions.value": fmt.Sprintf("%s %s", g.DeviceName, g.Version)}))
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
		url := fmt.Sprintf(model.CVE.MainResource(), "gargoyle")
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
		g.CveList = append(g.CveList, v.CVEID)
		totalScore += v.BaseScore
	}

	g.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if g.CveScore > 7 {
		g.Sensibility = "HIGH"
	} else if g.CveScore >= 4 && g.CveScore <= 7 {
		g.Sensibility = "MEDIUM"
	} else if g.CveScore < 4 {
		g.Sensibility = "LOW"
	}
	g.CveList = utils.RemoveDuplicates(g.CveList)
}

func (g *Gargoyle) PrintInfo() string { return model.Category.Router() + " | Gargoyle" }

func (g *Gargoyle) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         g.Category,
		DeviceName:       g.DeviceName,
		Version:          g.Version,
		CveList:          g.CveList,
		Sensibility:      g.Sensibility,
		CveScore:         g.CveScore,
		ExtraInformation: g.ExtraInformation,
	}
}
