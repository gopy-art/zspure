package bbnetworkcamera

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

type BbNetworkCamera struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (b *BbNetworkCamera) SetCategory(category ...string) {
	b.Category = model.Category.Camera()
}

func (b *BbNetworkCamera) SetDeviceName(device ...string) {
	b.DeviceName = "BB Camera"
}

func (b *BbNetworkCamera) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.response.body.body": "<title>BB-SW172 Network Camera</title>"},
	}
}

func (b *BbNetworkCamera) Filters(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	if val, ok := banner["response"].(map[string]interface{})["body"].(string); ok {
		if strings.Contains(val, "BB-SW172 Network Camera") &&
			!strings.Contains(val, "0<!DOCTYPE html>") &&
			!strings.Contains(val, "<p hidden>") {
			return true
		}
	}
	return false
}

func (b *BbNetworkCamera) DeviceScan(banner map[string]interface{}) bool {
	b.ExtraInformation.NewExtraInfo()
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if server, sok := val.(map[string]interface{})["server"].([]any); sok {
			b.ExtraInformation.SetExtraInfo("server", server[0].(string))
		}
	}
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if pl, pok := val.(map[string]interface{})["x_powered_by"].([]any); pok {
			b.ExtraInformation.SetExtraInfo("programming_language", pl[0].(string))
		}
	}
	return false
}

func (b *BbNetworkCamera) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": "BB-SW172",
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
		url := fmt.Sprintf(model.CVE.MainResource(), "BB-SW172")
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

	for _, vl := range CVE {
		b.CveList = append(b.CveList, vl.CVEID)
		totalScore += vl.BaseScore
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

func (b *BbNetworkCamera) PrintInfo() string { return model.Category.Camera() + " | BB Network Camera" }

func (b *BbNetworkCamera) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         b.Category,
		DeviceName:       b.DeviceName,
		Version:          b.Version,
		CveList:          b.CveList,
		Sensibility:      b.Sensibility,
		CveScore:         b.CveScore,
		ExtraInformation: b.ExtraInformation,
	}
}
