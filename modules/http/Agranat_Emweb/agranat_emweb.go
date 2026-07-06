package agranatemweb

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

type AgranatEmweb struct {
	Category    string                `json:"dvs_category"`
	DeviceName  string                `json:"device_name"`
	Version     string                `json:"version"`
	CveList     []string              `json:"cves"`
	Sensibility string                `json:"base_severity"`
	CveScore    float64               `json:"cve_score"`
	ExtraInfo   model.ModuleExtraInfo `json:"dvs_extra"`
}

func (a *AgranatEmweb) SetCategory(category ...string) {
	a.Category = model.Category.Controller()
}

func (a *AgranatEmweb) SetDeviceName(device ...string) {
	a.DeviceName = "Emweb"
}

func (a *AgranatEmweb) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.response.headers.server": "Agranat-EmWeb"},
	}
}

func (a *AgranatEmweb) Filters(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	if val, ok := banner["response"].(map[string]interface{})["headers"].(map[string]interface{})["server"].([]any); ok && len(val) > 0 {
		if str, ok := val[0].(string); ok && strings.Contains(strings.ToLower(str), "agranat-emweb") {
			if body, ok := banner["response"].(map[string]interface{})["body"].(string); ok {
				if body == "" {
					return true
				} else if !strings.Contains(body, "<html") && !strings.Contains(body, "</html>") {
					return true
				} else {
					return (len(body) < 100)
				}
			} else {
				return true
			}
		}
	}
	return false
}

func (a *AgranatEmweb) DeviceScan(banner map[string]interface{}) bool {
	a.ExtraInfo.NewExtraInfo()
	a.ExtraInfo.SetExtraInfo("product", "EmWeb")
	return false
}

func (a *AgranatEmweb) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": "agranat-emweb",
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
		url := fmt.Sprintf(model.CVE.MainResource(), "agranat-emweb")
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
		a.CveList = append(a.CveList, vl.CVEID)
		totalScore += vl.BaseScore
	}

	a.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if a.CveScore > 7 {
		a.Sensibility = "HIGH"
	} else if a.CveScore >= 4 && a.CveScore <= 7 {
		a.Sensibility = "MEDIUM"
	} else if a.CveScore < 4 {
		a.Sensibility = "LOW"
	}
	a.CveList = utils.RemoveDuplicates(a.CveList)
}

func (a *AgranatEmweb) PrintInfo() string { return model.Category.Controller() + " | Agranat Emweb" }

func (a *AgranatEmweb) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         a.Category,
		DeviceName:       a.DeviceName,
		Version:          a.Version,
		CveList:          a.CveList,
		Sensibility:      a.Sensibility,
		CveScore:         a.CveScore,
		ExtraInformation: a.ExtraInfo,
	}
}
