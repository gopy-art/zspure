package huawei

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

type HuaweiEG8141A5 struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (h *HuaweiEG8141A5) SetCategory(category ...string) {
	h.Category = model.Category.Router()
}

func (h *HuaweiEG8141A5) SetDeviceName(device ...string) {
	h.DeviceName = "Huawei EG8141A5-10"
}

func (a *HuaweiEG8141A5) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.response.body": "<title></title>"},
		{"result.response.body": "HostInfo = HostInfo.substring(0, HostInfo.lastIndexOf"},
		{"result.response.body": "<body class=\"mainbody\" onLoad=\"LoadFrame();\">"},
	}
}

func (h *HuaweiEG8141A5) Filters(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	if val, ok := banner["response"].(map[string]interface{})["body"]; ok {
		if (strings.Contains(val.(string), "<title></title>") &&
			strings.Contains(val.(string), "HostInfo = HostInfo.substring(0, HostInfo.lastIndexOf") &&
			strings.Contains(val.(string), "<body class=\"mainbody\" onLoad=\"LoadFrame();\">")) &&
			!strings.Contains(val.(string), "0<!DOCTYPE html>") &&
			!strings.Contains(val.(string), "<p hidden>") {
			return true
		}
	}
	return false
}

func (h *HuaweiEG8141A5) DeviceScan(banner map[string]interface{}) bool {
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
	return false
}

func (h *HuaweiEG8141A5) CveScan(els *handler.Elastic) {
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
		url := fmt.Sprintf(model.CVE.MainResource(), "huawei"+"%20"+"EG8141A5")
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

func (h *HuaweiEG8141A5) PrintInfo() string { return model.Category.Router() + " | Huawei EG8141A5-10" }

func (h *HuaweiEG8141A5) Result() model.ModuleStructure {
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
