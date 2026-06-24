package sensatronics

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

type Sensatronics struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (s *Sensatronics) SetCategory(category ...string) {
	s.Category = model.Category.Industrial()
}

func (s *Sensatronics) SetDeviceName(device ...string) {
	s.DeviceName = "Sensatronics"
}

func (s *Sensatronics) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.response.body": "Environmental Monitor"},
		{"result.response.body": "IT Temperature Monitor"},
		{"result.response.body": "Universal Temperature Monitor"},
	}
}

func (s *Sensatronics) Filters(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	if val, ok := banner["response"].(map[string]interface{})["body"]; ok {
		if strings.Contains(val.(string), "0<!DOCTYPE html>") &&
			strings.Contains(val.(string), "<p hidden>") {
			return false
		}
		if strings.Contains(val.(string), "<title>Environmental Monitor") || 
			strings.Contains(val.(string), "<title>IT Temperature Monitor") ||
			strings.Contains(val.(string), "<title>Universal Temperature Monitor") {
			return true
		}
	}
	return false
}

func (s *Sensatronics) DeviceScan(banner map[string]interface{}) bool {
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

	modelRe := regexp.MustCompile(`<TD>Model:</TD>\s*<TD[^>]*>\s*<BR>\s*</TD>\s*<TD>([^<]+)</TD>`)
	if matches := modelRe.FindStringSubmatch(banner["response"].(map[string]interface{})["body"].(string)); len(matches) > 1 {
		s.Version = matches[1]
	}

	firmwareRe := regexp.MustCompile(`Firmware Version:</TD><TD[^>]*><BR></TD><TD[^>]*><BR></TD><TD>([^<]+)</TD>`)
	if matches := firmwareRe.FindStringSubmatch(banner["response"].(map[string]interface{})["body"].(string)); len(matches) > 1 {
		fmt.Printf("%+v\n", matches)
		s.ExtraInformation.SetExtraInfo("firmware_version", matches[1])
	}

	serialRe := regexp.MustCompile(`<TD>Serial Number:</TD><TD[^>]*>([^<]+)</TD>`)
	if matches := serialRe.FindStringSubmatch(banner["response"].(map[string]interface{})["body"].(string)); len(matches) > 1 {
		s.ExtraInformation.SetExtraInfo("serial_number", matches[1])
	}

	return false
}

func (s *Sensatronics) CveScan(els *handler.Elastic) {
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
		url := fmt.Sprintf(model.CVE.MainResource(), "sensatronics%20"+s.Version)
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

func (s *Sensatronics) PrintInfo() string {
	return model.Category.Industrial() + " | Sensatronics"
}

func (s *Sensatronics) Result() model.ModuleStructure {
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
