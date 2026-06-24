package opnsense

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

type OPNsense struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (o *OPNsense) SetCategory(category ...string) {
	o.Category = model.Category.Firewall()
}

func (o *OPNsense) SetDeviceName(device ...string) {
	o.DeviceName = "OPNsense"
}

func (a *OPNsense) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.response.body": "<title>Login | OPNsense</title>"},
		{"result.response.body": "src=\"/ui/themes/opnsense/build/images/default-logo.svg?v="},
	}
}

func (o *OPNsense) Filters(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	if val, ok := banner["response"].(map[string]interface{})["body"]; ok {
		if (strings.Contains(val.(string), "<title>Login | OPNsense</title>") &&
			strings.Contains(val.(string), "src=\"/ui/themes/opnsense/build/images/default-logo.svg?v=")) &&
			!strings.Contains(val.(string), "0<!DOCTYPE html>") &&
			!strings.Contains(val.(string), "<p hidden>") {
			return true
		}
	}
	return false
}

func (o *OPNsense) DeviceScan(banner map[string]interface{}) bool {
	o.ExtraInformation.NewExtraInfo()
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if server, sok := val.(map[string]interface{})["server"].([]any); sok {
			o.ExtraInformation.SetExtraInfo("server", server[0].(string))
		}
	}
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if pl, pok := val.(map[string]interface{})["x_powered_by"].([]any); pok {
			o.ExtraInformation.SetExtraInfo("programming_language", pl[0].(string))
		}
	}
	return false
}

func (o *OPNsense) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{"cve.descriptions.value": fmt.Sprintf("%s %s", o.DeviceName, o.Version)}))
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
			strings.ToLower(strings.ReplaceAll(fmt.Sprintf("%v", o.DeviceName), " ", "%20")))
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
		o.CveList = append(o.CveList, v.CVEID)
		totalScore += v.BaseScore
	}

	o.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if o.CveScore > 7 {
		o.Sensibility = "HIGH"
	} else if o.CveScore >= 4 && o.CveScore <= 7 {
		o.Sensibility = "MEDIUM"
	} else if o.CveScore < 4 {
		o.Sensibility = "LOW"
	}
	o.CveList = utils.RemoveDuplicates(o.CveList)
}

func (o *OPNsense) PrintInfo() string { return model.Category.Firewall() + " | OPNsense" }

func (o *OPNsense) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         o.Category,
		DeviceName:       o.DeviceName,
		Version:          o.Version,
		CveList:          o.CveList,
		Sensibility:      o.Sensibility,
		CveScore:         o.CveScore,
		ExtraInformation: o.ExtraInformation,
	}
}
