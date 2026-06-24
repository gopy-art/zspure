package vivotek

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

type Vivotek struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (v *Vivotek) SetCategory(category ...string) {
	v.Category = model.Category.Camera()
}

func (v *Vivotek) SetDeviceName(device ...string) {
	v.DeviceName = "Vivotek"
}

func (a *Vivotek) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.response.body": "<title>VIVOTEK"},
		{"result.response.body": "console.log('for wretched IE, good bye animation')"},
	}
}

func (v *Vivotek) Filters(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	if val, ok := banner["response"].(map[string]interface{})["body"]; ok {
		if (strings.Contains(val.(string), "<title>VIVOTEK") &&
			strings.Contains(val.(string), "console.log('for wretched IE, good bye animation')")) &&
			!strings.Contains(val.(string), "0<!DOCTYPE html>") &&
			!strings.Contains(val.(string), "<p hidden>") {
			return true
		}
	}
	return false
}

func (v *Vivotek) DeviceScan(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	v.ExtraInformation.NewExtraInfo()
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if server, sok := val.(map[string]interface{})["server"].([]any); sok {
			v.ExtraInformation.SetExtraInfo("server", server[0].(string))
		}
	}
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if pl, pok := val.(map[string]interface{})["x_powered_by"].([]any); pok {
			v.ExtraInformation.SetExtraInfo("programming_language", pl[0].(string))
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

		if len(words) >= 2 {
			v.Version = words[1]
			return true
		}
	}
	return false
}

func (v *Vivotek) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{"cve.descriptions.value": fmt.Sprintf("%s %s", v.DeviceName, v.Version)}))
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
			strings.ToLower(strings.ReplaceAll(fmt.Sprintf("%v %v", v.DeviceName, v.Version), " ", "%20")))
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

	for _, cv := range CVE {
		v.CveList = append(v.CveList, cv.CVEID)
		totalScore += cv.BaseScore
	}

	v.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if v.CveScore > 7 {
		v.Sensibility = "HIGH"
	} else if v.CveScore >= 4 && v.CveScore <= 7 {
		v.Sensibility = "MEDIUM"
	} else if v.CveScore < 4 {
		v.Sensibility = "LOW"
	}
	v.CveList = utils.RemoveDuplicates(v.CveList)
}

func (v *Vivotek) PrintInfo() string { return model.Category.Camera() + " | Vivotek" }

func (v *Vivotek) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         v.Category,
		DeviceName:       v.DeviceName,
		Version:          v.Version,
		CveList:          v.CveList,
		Sensibility:      v.Sensibility,
		CveScore:         v.CveScore,
		ExtraInformation: v.ExtraInformation,
	}
}
