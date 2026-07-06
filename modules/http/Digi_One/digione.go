package digione

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

type DigiOne struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (d *DigiOne) SetCategory(category ...string) {
	d.Category = model.Category.Industrial()
}

func (d *DigiOne) SetDeviceName(device ...string) {
	d.DeviceName = "DigiOne"
}

func (d *DigiOne) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.response.body": "Digi One SP&nbsp;Configuration and Management"},
	}
}

func (d *DigiOne) Filters(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	if val, ok := banner["response"].(map[string]interface{})["body"].(string); ok {
		if strings.Contains(val, "Digi One SP&nbsp;Configuration and Management") &&
			!strings.Contains(val, "0<!DOCTYPE html>") &&
			!strings.Contains(val, "<p hidden>") {
			return true
		}
	}
	return false
}

func (d *DigiOne) DeviceScan(banner map[string]interface{}) bool {
	d.ExtraInformation.NewExtraInfo()
	d.ExtraInformation.SetExtraInfo("product", "One")
	d.ExtraInformation.SetExtraInfo("type", "SCADA Gateway")
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if server, sok := val.(map[string]interface{})["server"].([]any); sok {
			d.ExtraInformation.SetExtraInfo("server", server[0].(string))
		}
	}
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if pl, pok := val.(map[string]interface{})["x_powered_by"].([]any); pok {
			d.ExtraInformation.SetExtraInfo("programming_language", pl[0].(string))
		}
	}
	return false
}

func (d *DigiOne) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": d.DeviceName,
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
		url := fmt.Sprintf(model.CVE.MainResource(), "digione%20"+d.Version)
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
		d.CveList = append(d.CveList, vl.CVEID)
		totalScore += vl.BaseScore
	}

	d.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if d.CveScore > 7 {
		d.Sensibility = "HIGH"
	} else if d.CveScore >= 4 && d.CveScore <= 7 {
		d.Sensibility = "MEDIUM"
	} else if d.CveScore < 4 {
		d.Sensibility = "LOW"
	}
	d.CveList = utils.RemoveDuplicates(d.CveList)
}

func (d *DigiOne) PrintInfo() string { return model.Category.Industrial() + " | DigiOne" }

func (d *DigiOne) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         d.Category,
		DeviceName:       d.DeviceName,
		Version:          d.Version,
		CveList:          d.CveList,
		Sensibility:      d.Sensibility,
		CveScore:         d.CveScore,
		ExtraInformation: d.ExtraInformation,
	}
}
