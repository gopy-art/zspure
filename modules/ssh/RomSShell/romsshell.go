package romsshell

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"zspure/config"
	"zspure/config/cmd"
	"zspure/handler"
	"zspure/modules/model"
	"zspure/modules/ssh/os"
	"zspure/utils"
)

type RomSShell struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (r *RomSShell) SetCategory(category ...string) {
	r.Category = model.Category.Service()
}

func (r *RomSShell) SetDeviceName(device ...string) {
	r.DeviceName = "RomSShell"
}

func (r *RomSShell) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (r *RomSShell) Filters(banner map[string]interface{}) bool {
	if banner["server_id"] == nil {
		return false
	}
	if val, ok := banner["server_id"].(map[string]interface{}); ok && val != nil {
		if v, okk := val["raw"].(string); okk && strings.Contains(strings.ToLower(v), "romsshell") {
			return true
		}
	}
	return false
}

func (r *RomSShell) DeviceScan(banner map[string]interface{}) bool {
	r.ExtraInformation.NewExtraInfo()
	if ok, result := os.DetectOperatingSystems(banner["server_id"].(map[string]interface{})["raw"].(string)); ok {
		if result.Name != "" {
			r.ExtraInformation.SetExtraInfo("operating_system", result.Name)
		}
		if result.Version != "" {
			r.ExtraInformation.SetExtraInfo("os_version", result.Version)
		}
	}

	r.ExtraInformation.SetExtraInfo("manufacturer", "Allegro Software")
	re := regexp.MustCompile(`RomSShell_([\d.]+)`)
	matches := re.FindStringSubmatch(banner["server_id"].(map[string]interface{})["raw"].(string))
	if len(matches) > 1 {
		r.Version = matches[1]
		return true
	}
	return false
}

func (r *RomSShell) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0
	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": fmt.Sprintf("%v %v", r.DeviceName, r.Version),
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
			strings.ToLower(strings.ReplaceAll(fmt.Sprintf("%v %v", r.DeviceName, r.Version), " ", "%20")))
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
		r.CveList = append(r.CveList, v.CVEID)
		totalScore += v.BaseScore
	}

	r.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if r.CveScore > 7 {
		r.Sensibility = "HIGH"
	} else if r.CveScore >= 4 && r.CveScore <= 7 {
		r.Sensibility = "MEDIUM"
	} else if r.CveScore < 4 {
		r.Sensibility = "LOW"
	}
	r.CveList = utils.RemoveDuplicates(r.CveList)
}

func (r *RomSShell) PrintInfo() string { return model.Category.Service() + " | RomSShell" }

func (r *RomSShell) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         r.Category,
		DeviceName:       r.DeviceName,
		Version:          r.Version,
		CveList:          r.CveList,
		Sensibility:      r.Sensibility,
		CveScore:         r.CveScore,
		ExtraInformation: r.ExtraInformation,
	}
}
