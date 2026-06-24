package windowsserver

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

type WindowsServer struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (w *WindowsServer) SetCategory(category ...string) {
	w.Category = model.Category.WebServer()
}

func (w *WindowsServer) SetDeviceName(device ...string) {
	w.DeviceName = "Windows Server"
}

func (a *WindowsServer) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.response.body": "<img src=\"iisstart.png\" alt=\"IIS"},
		{"result.response.body": "<title>IIS Windows Server</title>"},
		{"result.response.body": "<title>IIS Windows</title>"},
		{"result.response.body": "<title>Microsoft Internet Information Services 8</title>"},
	}
}

func (w *WindowsServer) Filters(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	if val, ok := banner["response"].(map[string]interface{})["body"]; ok {
		if (strings.Contains(val.(string), "<img src=\"iisstart.png\" alt=\"IIS") ||
			strings.Contains(val.(string), "<title>IIS Windows Server</title>") ||
			strings.Contains(val.(string), "<title>IIS Windows</title>") ||
			strings.Contains(val.(string), "<title>Microsoft Internet Information Services 8</title>")) &&
			!strings.Contains(val.(string), "0<!DOCTYPE html>") &&
			!strings.Contains(val.(string), "<p hidden>") {
			return true
		}
	}
	return false
}

func (w *WindowsServer) DeviceScan(banner map[string]interface{}) bool {
	w.ExtraInformation.NewExtraInfo()
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if server, sok := val.(map[string]interface{})["server"].([]any); sok {
			w.ExtraInformation.SetExtraInfo("server", server[0].(string))
		}
	}
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if pl, pok := val.(map[string]interface{})["x_powered_by"].([]any); pok {
			w.ExtraInformation.SetExtraInfo("programming_language", pl[0].(string))
		}
	}
	return false
}

func (w *WindowsServer) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{"cve.descriptions.value": fmt.Sprintf("%s %s", w.DeviceName, w.Version)}))
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
			strings.ToLower(strings.ReplaceAll(fmt.Sprintf("%v", w.DeviceName), " ", "%20")))
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
		w.CveList = append(w.CveList, cv.CVEID)
		totalScore += cv.BaseScore
	}

	w.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if w.CveScore > 7 {
		w.Sensibility = "HIGH"
	} else if w.CveScore >= 4 && w.CveScore <= 7 {
		w.Sensibility = "MEDIUM"
	} else if w.CveScore < 4 {
		w.Sensibility = "LOW"
	}
	w.CveList = utils.RemoveDuplicates(w.CveList)
}

func (w *WindowsServer) PrintInfo() string { return model.Category.WebServer() + " | Windows Server" }

func (w *WindowsServer) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         w.Category,
		DeviceName:       w.DeviceName,
		Version:          w.Version,
		CveList:          w.CveList,
		Sensibility:      w.Sensibility,
		CveScore:         w.CveScore,
		ExtraInformation: w.ExtraInformation,
	}
}
