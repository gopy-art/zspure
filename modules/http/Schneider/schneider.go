package schneider

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

type SchneiderIndustrialWebControl struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (s *SchneiderIndustrialWebControl) SetCategory(category ...string) {
	s.Category = model.Category.Industrial()
}

func (s *SchneiderIndustrialWebControl) SetDeviceName(device ...string) {
	s.DeviceName = "Schneider Industrial Web Control"
}

func (s *SchneiderIndustrialWebControl) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.response.body": "Schneider Electric Telecontrol - Industrial Web Control"},
	}
}

func (s *SchneiderIndustrialWebControl) Filters(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	if val, ok := banner["response"].(map[string]interface{})["body"]; ok {
		if strings.Contains(val.(string), "0<!DOCTYPE html>") &&
			strings.Contains(val.(string), "<p hidden>") {
			return false
		}
		if strings.Contains(val.(string), "<title>Schneider Electric Telecontrol - Industrial Web Control</title>") {
			return true
		}
	}
	return false
}

func (s *SchneiderIndustrialWebControl) DeviceScan(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	s.ExtraInformation.NewExtraInfo()
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if server, sok := val.(map[string]interface{})["server"].([]any); sok {
			s.ExtraInformation.SetExtraInfo("server", server[0].(string))
		}
	}

	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if pl, pok := val.(map[string]interface{})["x_powered_by"].([]any); pok {
			s.ExtraInformation.SetExtraInfo("programming_language", pl[0].(string))
		}
	}

	re := regexp.MustCompile(`<small>([A-Za-z]+)\s*-\s*([\d.]+)`)
    matches := re.FindStringSubmatch(banner["response"].(map[string]interface{})["body"].(string))
    if len(matches) > 2 {
        s.ExtraInformation.SetExtraInfo("application", matches[1])
        s.ExtraInformation.SetExtraInfo("firmware_version", matches[2])
    }

	return false
}

func (s *SchneiderIndustrialWebControl) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{"cve.descriptions.value": fmt.Sprintf("%s %s", s.DeviceName, s.Version)}))
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
		url := fmt.Sprintf(model.CVE.MainResource(), "schneider")
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
		s.CveList = append(s.CveList, v.CVEID)
		totalScore += v.BaseScore
	}

	s.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if s.CveScore > 7 {
		s.Sensibility = "HIGH"
	} else if s.CveScore >= 4 && s.CveScore <= 7 {
		s.Sensibility = "MEDIUM"
	} else if s.CveScore < 4 {
		s.Sensibility = "LOW"
	}
	s.CveList = utils.RemoveDuplicates(s.CveList)
}

func (s *SchneiderIndustrialWebControl) PrintInfo() string { return model.Category.Industrial() + " | Schneider Industrial Web Control" }

func (s *SchneiderIndustrialWebControl) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         s.Category,
		DeviceName:       s.DeviceName,
		Version:          s.Version,
		CveList:          s.CveList,
		Sensibility:      s.Sensibility,
		CveScore:         s.CveScore,
		ExtraInformation: s.ExtraInformation,
	}
}
