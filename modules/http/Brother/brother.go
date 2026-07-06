package brother

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
)

var modelType string

type Brother struct {
	Category    string                `json:"dvs_category"`
	DeviceName  string                `json:"device_name"`
	Version     string                `json:"version"`
	CveList     []string              `json:"cves"`
	Sensibility string                `json:"base_severity"`
	CveScore    float64               `json:"cve_score"`
	ExtraInfo   model.ModuleExtraInfo `json:"dvs_extra"`
}

func (b *Brother) SetCategory(category ...string) {
	b.Category = model.Category.Printer()
}

func (b *Brother) SetDeviceName(device ...string) {
	b.DeviceName = "Brother"
}

func (b *Brother) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.response.body": "<title>Brother"},
	}
}

func (b *Brother) Filters(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	if val, ok := banner["response"].(map[string]interface{})["body"].(string); ok {
		if (strings.Contains(val, "<title>Brother") &&
			strings.Contains(val, "Brother Industries")) &&
			!strings.Contains(val, "0<!DOCTYPE html>") &&
			!strings.Contains(val, "<p hidden>") {
			return true
		}
	}
	return false
}

func (b *Brother) DeviceScan(banner map[string]interface{}) bool {
	b.ExtraInfo.NewExtraInfo()
	if val, ok := banner["response"].(map[string]interface{})["body"].(string); ok {
		re := regexp.MustCompile(`Brother\s+([A-Za-z0-9\-]+)`)
		matches := re.FindStringSubmatch(val)
		if len(matches) > 1 {
			modelType = matches[1]
			b.ExtraInfo.SetExtraInfo("product", matches[1])
		}
	}
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if server, sok := val.(map[string]interface{})["server"].([]any); sok {
			b.ExtraInfo.SetExtraInfo("server", server[0].(string))
		}
	}
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if pl, pok := val.(map[string]interface{})["x_powered_by"].([]any); pok {
			b.ExtraInfo.SetExtraInfo("programming_language", pl[0].(string))
		}
	}
	return false
}

func (b *Brother) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": b.DeviceName + " " + modelType,
		}))
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
		url := fmt.Sprintf(model.CVE.MainResource(), b.DeviceName+"%20"+modelType)
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
		b.CveList = append(b.CveList, v.CVEID)
		totalScore += v.BaseScore
	}

	b.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if b.CveScore > 7 {
		b.Sensibility = "HIGH"
	} else if b.CveScore >= 4 && b.CveScore <= 7 {
		b.Sensibility = "MEDIUM"
	} else if b.CveScore < 4 {
		b.Sensibility = "LOW"
	}
	b.CveList = utils.RemoveDuplicates(b.CveList)
}

func (b *Brother) PrintInfo() string { return model.Category.Printer() + " | Brother" }

func (b *Brother) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         b.Category,
		DeviceName:       b.DeviceName,
		Version:          b.Version,
		CveList:          b.CveList,
		Sensibility:      b.Sensibility,
		CveScore:         b.CveScore,
		ExtraInformation: b.ExtraInfo,
	}
}
