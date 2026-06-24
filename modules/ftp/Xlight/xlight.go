package xlight

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

type XlightWindowsSystems struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (x *XlightWindowsSystems) SetCategory(category ...string) {
	x.Category = model.Category.Service()
}

func (x *XlightWindowsSystems) SetDeviceName(device ...string) {
	x.DeviceName = "Xlight Windows Systems"
}

func (x *XlightWindowsSystems) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (x *XlightWindowsSystems) Filters(banner map[string]interface{}) bool {
	if banner["banner"] != nil &&
		banner["banner"].(string) != "" &&
		strings.Contains(strings.ToLower(banner["banner"].(string)), strings.ToLower("Xlight FTP Server")) {
		return true
	}
	return false
}

func (x *XlightWindowsSystems) DeviceScan(banner map[string]interface{}) bool {
	re := regexp.MustCompile(`Xlight FTP Server\s+([\d.]+)`)
	matches := re.FindStringSubmatch(banner["banner"].(string))
	if len(matches) > 1 {
		x.Version = matches[1]
		return true
	}
	return false
}

func (x *XlightWindowsSystems) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": fmt.Sprintf("xlight %v", x.Version),
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
			strings.ToLower(strings.ReplaceAll(fmt.Sprintf("xlight %v", x.Version), " ", "%20")))
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
		x.CveList = append(x.CveList, v.CVEID)
		totalScore += v.BaseScore
	}

	x.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if x.CveScore > 7 {
		x.Sensibility = "HIGH"
	} else if x.CveScore >= 4 && x.CveScore <= 7 {
		x.Sensibility = "MEDIUM"
	} else if x.CveScore < 4 {
		x.Sensibility = "LOW"
	}
	x.CveList = utils.RemoveDuplicates(x.CveList)
}

func (x *XlightWindowsSystems) PrintInfo() string {
	return model.Category.Service() + " | Xlight Windows Systems"
}

func (x *XlightWindowsSystems) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    x.Category,
		DeviceName:  x.DeviceName,
		Version:     x.Version,
		CveList:     x.CveList,
		Sensibility: x.Sensibility,
		CveScore:    x.CveScore,
	}
}
