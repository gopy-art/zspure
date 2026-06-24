package officeconnect

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

type HPOfficeConnectSwitch struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (h *HPOfficeConnectSwitch) SetCategory(category ...string) {
	h.Category = model.Category.Switch()
}

func (h *HPOfficeConnectSwitch) SetDeviceName(device ...string) {
	h.DeviceName = "HP Office Connect Switch"
}

func (h *HPOfficeConnectSwitch) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.response.body": "<title>HPE OfficeConnect Switch"},
	}
}

func (h *HPOfficeConnectSwitch) Filters(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	if val, ok := banner["response"].(map[string]interface{})["body"]; ok {
		if strings.Contains(val.(string), "0<!DOCTYPE html>") &&
			strings.Contains(val.(string), "<p hidden>") {
			return false
		}
		if strings.Contains(val.(string), "<title>HPE OfficeConnect Switch") {
			return true
		}
	}
	return false
}

func (h *HPOfficeConnectSwitch) DeviceScan(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	h.ExtraInformation.NewExtraInfo()
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if server, sok := val.(map[string]interface{})["server"].([]any); sok {
			h.ExtraInformation.SetExtraInfo("server", server[0].(string))
		}
	}

	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if pl, pok := val.(map[string]interface{})["x_powered_by"].([]any); pok {
			h.ExtraInformation.SetExtraInfo("programming_language", pl[0].(string))
		}
	}

    re := regexp.MustCompile(`HPE OfficeConnect Switch (\d+ \d+G(?: PoE\+)?) \((\d+W)\) ([A-Z0-9]+)`)
    matches := re.FindStringSubmatch(banner["response"].(map[string]interface{})["body"].(string))
    if len(matches) > 3 {
        h.ExtraInformation.SetExtraInfo("hardware_configuration", matches[1])
		h.ExtraInformation.SetExtraInfo("power_budget", matches[2])
        h.Version = matches[3]
    }

	return false
}

func (h *HPOfficeConnectSwitch) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{"cve.descriptions.value": fmt.Sprintf("%s %s", h.DeviceName, h.Version)}))
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
		url := fmt.Sprintf(model.CVE.MainResource(), "officeconnect%20"+h.Version)
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
		h.CveList = append(h.CveList, v.CVEID)
		totalScore += v.BaseScore
	}

	h.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if h.CveScore > 7 {
		h.Sensibility = "HIGH"
	} else if h.CveScore >= 4 && h.CveScore <= 7 {
		h.Sensibility = "MEDIUM"
	} else if h.CveScore < 4 {
		h.Sensibility = "LOW"
	}
	h.CveList = utils.RemoveDuplicates(h.CveList)
}

func (h *HPOfficeConnectSwitch) PrintInfo() string { return model.Category.Switch() + " | HP Office Connect Switch" }

func (h *HPOfficeConnectSwitch) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         h.Category,
		DeviceName:       h.DeviceName,
		Version:          h.Version,
		CveList:          h.CveList,
		Sensibility:      h.Sensibility,
		CveScore:         h.CveScore,
		ExtraInformation: h.ExtraInformation,
	}
}