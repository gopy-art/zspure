package lexmark

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

type Lexmark struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (l *Lexmark) SetCategory(category ...string) {
	l.Category = model.Category.Printer()
}

func (l *Lexmark) SetDeviceName(device ...string) {
	l.DeviceName = "Lexmark"
}

func (l *Lexmark) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (l *Lexmark) Filters(banner map[string]interface{}) bool {
	if banner["banner"] != nil && banner["banner"].(string) != "" && strings.Contains(banner["banner"].(string), "Lexmark") {
		return true
	}
	return false
}

func (l *Lexmark) DeviceScan(banner map[string]interface{}) bool {
	l.ExtraInformation.NewExtraInfo()
	modelRe := regexp.MustCompile(`Lexmark\s+([A-Za-z0-9]+)`)
	if matches := modelRe.FindStringSubmatch(banner["banner"].(string)); len(matches) > 1 {
		l.ExtraInformation.SetExtraInfo("model", matches[1])
	}

	versionRe := regexp.MustCompile(`FTP Server\s+([A-Za-z0-9.]+)`)
	if matches := versionRe.FindStringSubmatch(banner["banner"].(string)); len(matches) > 1 {
		l.Version = matches[1]
	}
	return false
}

func (l *Lexmark) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": fmt.Sprintf("%v %v", l.DeviceName, l.Version),
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
		url := fmt.Sprintf(model.CVE.MainResource(),
			strings.ToLower(strings.ReplaceAll(fmt.Sprintf("%v %v", l.DeviceName, l.Version), " ", "%20")))
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
		l.CveList = append(l.CveList, v.CVEID)
		totalScore += v.BaseScore
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

func (l *Lexmark) PrintInfo() string {
	return model.Category.Printer() + " | Lexmark"
}

func (l *Lexmark) Result() model.ModuleStructure {
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
