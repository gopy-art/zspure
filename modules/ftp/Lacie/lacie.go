package lacie

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

type Lacie struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (l *Lacie) SetCategory(category ...string) {
	l.Category = model.Category.NetworkStorage()
}

func (l *Lacie) SetDeviceName(device ...string) {
	l.DeviceName = "Lacie"
}

func (l *Lacie) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (l *Lacie) Filters(banner map[string]interface{}) bool {
	if banner["banner"] == nil {
		return false
	}
	if val, ok := banner["banner"].(string); ok {
		if strings.Contains(val, "LaCie") || strings.Contains(val, "NetworkSpace2") {
			return true
		}
	}
	return false
}

func (l *Lacie) DeviceScan(banner map[string]interface{}) bool {
	if val, ok := banner["banner"]; ok {
		l.ExtraInformation.NewExtraInfo()
		bannerStr := fmt.Sprintf("%v", val)
		if strings.Contains(bannerStr, "LaCie") {
			if strings.Contains(bannerStr, "CloudBox") {
				l.ExtraInformation.SetExtraInfo("product", "CloudBox")
			} else if strings.Contains(bannerStr, "LaCie-5big") {
				l.ExtraInformation.SetExtraInfo("product", "5Big")
			} else if strings.Contains(bannerStr, "NetworkSpace2") {
				l.ExtraInformation.SetExtraInfo("product", "Network Space 2")
			} else if strings.Contains(bannerStr, "LaCie-2big") {
				l.ExtraInformation.SetExtraInfo("product", "2Big")
			}
			return true
		}
	}
	return false
}

func (l *Lacie) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": l.DeviceName,
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
		url := fmt.Sprintf(model.CVE.MainResource(), "lacie")
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
		l.CveList = append(l.CveList, vl.CVEID)
		totalScore += vl.BaseScore
	}

	l.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if l.CveScore > 7 {
		l.Sensibility = "HIGH"
	} else if l.CveScore >= 4 && l.CveScore <= 7 {
		l.Sensibility = "MEDIUM"
	} else if l.CveScore < 4 {
		l.Sensibility = "LOW"
	}
	l.CveList = utils.RemoveDuplicates(l.CveList)
}

func (l *Lacie) PrintInfo() string { return model.Category.NetworkStorage() + " | Lacie" }

func (l *Lacie) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         l.Category,
		DeviceName:       l.DeviceName,
		Version:          l.Version,
		CveList:          l.CveList,
		Sensibility:      l.Sensibility,
		CveScore:         l.CveScore,
		ExtraInformation: l.ExtraInformation,
	}
}
