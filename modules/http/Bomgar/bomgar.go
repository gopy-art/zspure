package bomgar

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

type Bomgar struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (b *Bomgar) SetCategory(category ...string) {
	b.Category = model.Category.Controller()
}

func (b *Bomgar) SetDeviceName(device ...string) {
	b.DeviceName = "Bomgar"
}

func (b *Bomgar) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.response.headers.server": "Bomgar"},
	}
}

func (b *Bomgar) Filters(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	if val, ok := banner["response"].(map[string]interface{})["headers"].(map[string]interface{})["server"].([]any); ok {
		if str, ok := val[0].(string); ok && strings.Contains(str, "Bomgar") {
			if body, ok := banner["response"].(map[string]interface{})["body"].(string); ok {
				if body == "" {
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

func (b *Bomgar) DeviceScan(banner map[string]interface{}) bool {
	return false
}

func (b *Bomgar) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": b.DeviceName,
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
		url := fmt.Sprintf(model.CVE.MainResource(), b.DeviceName)
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

func (b *Bomgar) PrintInfo() string { return model.Category.Controller() + " | Bomgar" }

func (b *Bomgar) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    b.Category,
		DeviceName:  b.DeviceName,
		Version:     b.Version,
		CveList:     b.CveList,
		Sensibility: b.Sensibility,
		CveScore:    b.CveScore,
	}
}
