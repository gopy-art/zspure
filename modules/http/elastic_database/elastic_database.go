package elasticdatabase

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

type ElasticDatabase struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (e *ElasticDatabase) SetCategory(category ...string) {
	e.Category = model.Category.Database()
}

func (e *ElasticDatabase) SetDeviceName(device ...string) {
	e.DeviceName = "ElasticSearch"
}

func (a *ElasticDatabase) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.response.body": "\"cluster_name\" : \"elasticsearch\""},
		{"result.response.body": "{\"error\":{\"root_cause\":[{\"type\""},
	}
}

func (e *ElasticDatabase) Filters(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	if val, ok := banner["response"].(map[string]interface{})["body"]; ok {
		if (strings.Contains(val.(string), "\"cluster_name\" : \"elasticsearch\"") ||
			strings.Contains(val.(string), "{\"error\":{\"root_cause\":[{\"type\"")) &&
			!strings.Contains(val.(string), "0<!DOCTYPE html>") &&
			!strings.Contains(val.(string), "<p hidden>") {
			return true
		}
	}
	return false
}

func (e *ElasticDatabase) DeviceScan(banner map[string]interface{}) bool {
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
	return false
}

func (e *ElasticDatabase) CveScan(els *handler.Elastic) {
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
		url := fmt.Sprintf(model.CVE.MainResource(), "elasticsearch")
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

func (e *ElasticDatabase) PrintInfo() string { return model.Category.Database() + " | ElasticSearch" }

func (e *ElasticDatabase) Result() model.ModuleStructure {
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
