package netcore

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

type NetCore struct {
	Category    string                `json:"dvs_category"`
	DeviceName  string                `json:"device_name"`
	Version     string                `json:"version"`
	CveList     []string              `json:"cves"`
	Sensibility string                `json:"base_severity"`
	CveScore    float64               `json:"cve_score"`
	ExtraInfo   model.ModuleExtraInfo `json:"dvs_extra"`
}

var modelType string

func (n *NetCore) SetCategory(category ...string) {
	n.Category = model.Category.Router()
}

func (n *NetCore) SetDeviceName(device ...string) {
	n.DeviceName = "Netcore"
}

func (n *NetCore) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.response.headers.www_authenticate": "TR069 client CLI Server"},
	}
}

func (n *NetCore) Filters(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	if val, ok := banner["response"].(map[string]interface{})["headers"].(map[string]interface{}); ok && len(val) > 0 {
		if strings.Contains(strings.ToLower(fmt.Sprintf("%v", val)), "basic realm=\"netcore") {
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

func (n *NetCore) DeviceScan(banner map[string]interface{}) bool {
	n.ExtraInfo.NewExtraInfo()
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		re := regexp.MustCompile(`NETCORE\s+([A-Za-z0-9]+)`)
		matches := re.FindStringSubmatch(fmt.Sprintf("%v", val))
		if len(matches) > 1 {
			n.ExtraInfo.SetExtraInfo("product", matches[1])
			modelType = matches[1]
			return true
		}
	}
	return false
}

func (n *NetCore) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": n.DeviceName + " " + modelType,
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
		url := fmt.Sprintf(model.CVE.MainResource(), n.DeviceName+"%20"+modelType)
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
		n.CveList = append(n.CveList, vl.CVEID)
		totalScore += vl.BaseScore
	}

	n.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if n.CveScore > 7 {
		n.Sensibility = "HIGH"
	} else if n.CveScore >= 4 && n.CveScore <= 7 {
		n.Sensibility = "MEDIUM"
	} else if n.CveScore < 4 {
		n.Sensibility = "LOW"
	}
	n.CveList = utils.RemoveDuplicates(n.CveList)
}

func (n *NetCore) PrintInfo() string { return model.Category.Router() + " | Netcore" }

func (n *NetCore) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         n.Category,
		DeviceName:       n.DeviceName,
		Version:          n.Version,
		CveList:          n.CveList,
		Sensibility:      n.Sensibility,
		CveScore:         n.CveScore,
		ExtraInformation: n.ExtraInfo,
	}
}
