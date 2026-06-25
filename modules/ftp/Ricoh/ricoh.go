package ricoh

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

type Ricoh struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (r *Ricoh) SetCategory(category ...string) {
	r.Category = model.Category.Printer()
}

func (r *Ricoh) SetDeviceName(device ...string) {
	r.DeviceName = "Ricoh"
}

func (r *Ricoh) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (r *Ricoh) Filters(banner map[string]interface{}) bool {
	if banner["banner"] != nil && banner["banner"].(string) != "" && strings.Contains(strings.ToLower(banner["banner"].(string)), strings.ToLower("220 RICOH")) {
		return true
	}
	return false
}

func (r *Ricoh) DeviceScan(banner map[string]interface{}) bool {
	r.ExtraInformation.NewExtraInfo()
	modelRe := regexp.MustCompile(`RICOH\s+([A-Za-z0-9\s]+?)\s+FTP server`)
	if matches := modelRe.FindStringSubmatch(banner["banner"].(string)); len(matches) > 1 {
		r.ExtraInformation.SetExtraInfo("model", matches[1])
	}

	versionRe := regexp.MustCompile(`\(([\d.]+)\)`)
	if matches := versionRe.FindStringSubmatch(banner["banner"].(string)); len(matches) > 1 {
		r.Version = matches[1]
	}
	return false
}

func (r *Ricoh) CveScan(els *handler.Elastic) {
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

func (r *Ricoh) PrintInfo() string {
	return model.Category.Printer() + " | Ricoh"
}

func (r *Ricoh) Result() model.ModuleStructure {
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
