package ipbuffer

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

type IPBufferWebServer struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (i *IPBufferWebServer) SetCategory(category ...string) {
	i.Category = model.Category.Industrial()
}

func (i *IPBufferWebServer) SetDeviceName(device ...string) {
	i.DeviceName = "Scannex"
}

func (i *IPBufferWebServer) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.response.body": "<title>ip.buffer webserver</title>"},
	}
}

func (i *IPBufferWebServer) Filters(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	if val, ok := banner["response"].(map[string]interface{})["body"]; ok {
		if strings.Contains(val.(string), "<title>ip.buffer webserver</title>") &&
			!strings.Contains(val.(string), "0<!DOCTYPE html>") &&
			!strings.Contains(val.(string), "<p hidden>") {
			return true
		}
	}
	return false
}

func (i *IPBufferWebServer) DeviceScan(banner map[string]interface{}) bool {
	i.ExtraInformation.NewExtraInfo()
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if server, sok := val.(map[string]interface{})["server"].([]any); sok {
			i.ExtraInformation.SetExtraInfo("server", server[0].(string))
		}
	}
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if pl, pok := val.(map[string]interface{})["x_powered_by"].([]any); pok {
			i.ExtraInformation.SetExtraInfo("programming_language", pl[0].(string))
		}
	}

	i.ExtraInformation.SetExtraInfo("product", "ip.buffer")
	if val, ok := banner["response"].(map[string]interface{})["body"].(string); ok {
		re := regexp.MustCompile(`Version\s+([^\s<]+)`)
		matches := re.FindStringSubmatch(val)
		if len(matches) > 1 {
			i.Version = matches[1]
		}
	}

	return false
}

func (i *IPBufferWebServer) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{"cve.descriptions.value": fmt.Sprintf("%s %s", i.DeviceName, i.Version)}))
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
		url := fmt.Sprintf(model.CVE.MainResource(), "scannex%20"+i.Version)
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
		i.CveList = append(i.CveList, v.CVEID)
		totalScore += v.BaseScore
	}

	i.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if i.CveScore > 7 {
		i.Sensibility = "HIGH"
	} else if i.CveScore >= 4 && i.CveScore <= 7 {
		i.Sensibility = "MEDIUM"
	} else if i.CveScore < 4 {
		i.Sensibility = "LOW"
	}
	i.CveList = utils.RemoveDuplicates(i.CveList)
}

func (i *IPBufferWebServer) PrintInfo() string { return model.Category.Industrial() + " | Scannex" }

func (i *IPBufferWebServer) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         i.Category,
		DeviceName:       i.DeviceName,
		Version:          i.Version,
		CveList:          i.CveList,
		Sensibility:      i.Sensibility,
		CveScore:         i.CveScore,
		ExtraInformation: i.ExtraInformation,
	}
}