package vsftpd

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

type VsFTPdLinuxSystems struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (v *VsFTPdLinuxSystems) SetCategory(category ...string) {
	v.Category = model.Category.Service()
}

func (v *VsFTPdLinuxSystems) SetDeviceName(device ...string) {
	v.DeviceName = "VsFtpd Linux Systems"
}

func (v *VsFTPdLinuxSystems) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (v *VsFTPdLinuxSystems) Filters(banner map[string]interface{}) bool {
	if banner["banner"] != nil && banner["banner"].(string) != "" && strings.Contains(banner["banner"].(string), "vsFTPd") {
		return true
	}
	return false
}

func (v *VsFTPdLinuxSystems) DeviceScan(banner map[string]interface{}) bool {
	re := regexp.MustCompile(`\([^)]*?\s+([\d.]+)\)`)
	matches := re.FindStringSubmatch(banner["banner"].(string))
	if len(matches) > 1 {
		v.Version = matches[1]
		return true
	}
	return false
}

func (v *VsFTPdLinuxSystems) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": fmt.Sprintf("vsftpd %v", v.Version),
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
			strings.ToLower(strings.ReplaceAll(fmt.Sprintf("vsftpd %v", v.Version), " ", "%20")))
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

func (v *VsFTPdLinuxSystems) PrintInfo() string {
	return model.Category.Service() + " | VsFtpd Linux Systems"
}

func (v *VsFTPdLinuxSystems) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    v.Category,
		DeviceName:  v.DeviceName,
		Version:     v.Version,
		CveList:     v.CveList,
		Sensibility: v.Sensibility,
		CveScore:    v.CveScore,
	}
}
