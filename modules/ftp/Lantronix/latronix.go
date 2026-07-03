package lantronix

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

type Lantronix struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (l *Lantronix) SetCategory(category ...string) {
	l.Category = model.Category.Industrial()
}

func (l *Lantronix) SetDeviceName(device ...string) {
	l.DeviceName = "Lantronix"
}

func (l *Lantronix) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (l *Lantronix) Filters(banner map[string]interface{}) bool {
	if banner["banner"] == nil {
		return false
	}
	if val, ok := banner["banner"].(string); ok {
		productRe := regexp.MustCompile(`(?i)^220 FTP Version (\d+\.\d+) on EPS2-100`)
		if matches := productRe.FindStringSubmatch(val); matches != nil {
			return true
		}
	}
	return false
}

func (l *Lantronix) DeviceScan(banner map[string]interface{}) bool {
	if val, ok := banner["banner"].(string); ok {
		productRe := regexp.MustCompile(`(?i)^220 FTP Version (\d+\.\d+) on EPS2-100`)
		if matches := productRe.FindStringSubmatch(val); matches != nil {
			l.Version = matches[1]
			return true
		}
	}
	return false
}

func (l *Lantronix) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": l.DeviceName+" "+l.Version,
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
		url := fmt.Sprintf(model.CVE.MainResource(), strings.ToLower(strings.ReplaceAll(fmt.Sprintf("%v %v", l.DeviceName, l.Version), " ", "%20")))
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

func (l *Lantronix) PrintInfo() string { return model.Category.Industrial() + " | Lantronix" }

func (l *Lantronix) Result() model.ModuleStructure {
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
