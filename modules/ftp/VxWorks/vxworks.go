package vxworks

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

type VxWorksSystems struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (v *VxWorksSystems) SetCategory(category ...string) {
	v.Category = model.Category.Industrial()
}

func (v *VxWorksSystems) SetDeviceName(device ...string) {
	v.DeviceName = "VxWorks Server"
}

func (v *VxWorksSystems) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (v *VxWorksSystems) Filters(banner map[string]interface{}) bool {
	if banner["banner"] != nil &&
		banner["banner"].(string) != "" &&
		strings.Contains(strings.ToLower(banner["banner"].(string)), strings.ToLower("VxWorks")) &&
		!strings.Contains(strings.ToLower(banner["banner"].(string)), strings.ToLower("Tenor Multipath Switch")) {
		return true
	}
	return false
}

func (v *VxWorksSystems) DeviceScan(banner map[string]interface{}) bool {
	re := regexp.MustCompile(`\(([^)]+)\)`)
	matches := re.FindStringSubmatch(banner["banner"].(string))
	if len(matches) > 1 {
		if strings.Contains(matches[1], "VxWorks") {
			v.Version = strings.Split(matches[1], "VxWorks")[1]
			return true
		}
		v.Version = matches[1]
		return true
	}
	return false
}

func (v *VxWorksSystems) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": "VxWorks%20"+v.Version,
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
		url := fmt.Sprintf(model.CVE.MainResource(), "VxWorks%20"+v.Version)
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
		v.CveList = append(v.CveList, vl.CVEID)
		totalScore += vl.BaseScore
	}

	v.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if v.CveScore > 7 {
		v.Sensibility = "HIGH"
	} else if v.CveScore >= 4 && v.CveScore <= 7 {
		v.Sensibility = "MEDIUM"
	} else if v.CveScore < 4 {
		v.Sensibility = "LOW"
	}
	v.CveList = utils.RemoveDuplicates(v.CveList)
}

func (v *VxWorksSystems) PrintInfo() string { return model.Category.Industrial() + " | VxWorks Server" }

func (v *VxWorksSystems) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    v.Category,
		DeviceName:  v.DeviceName,
		Version:     v.Version,
		CveList:     v.CveList,
		Sensibility: v.Sensibility,
		CveScore:    v.CveScore,
	}
}
