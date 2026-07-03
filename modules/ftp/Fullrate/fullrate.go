package fullrate

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

type Fullrate struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (f *Fullrate) SetCategory(category ...string) {
	f.Category = model.Category.Router()
}

func (f *Fullrate) SetDeviceName(device ...string) {
	f.DeviceName = "Fullrate"
}

func (f *Fullrate) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (f *Fullrate) Filters(banner map[string]interface{}) bool {
	if banner["banner"] == nil {
		return false
	}
	if val, ok := banner["banner"].(string); ok {
		if strings.Contains(val, "Fullrate") && strings.Contains(val, "FTP") {
			return true
		}
	}
	return false
}

func (f *Fullrate) DeviceScan(banner map[string]interface{}) bool {
	if val, ok := banner["banner"]; ok {
		bannerStr := fmt.Sprintf("%v", val)
		if strings.Contains(bannerStr, "Fullrate") {
			ftpVersionRe := regexp.MustCompile(`(?i)^220 Fullrate FTP version (\d+\.\d+) ready at`)
			matches := ftpVersionRe.FindStringSubmatch(bannerStr)
			if len(matches) > 1 {
				f.Version = matches[1]
				return true
			}
		}
	}
	return false
}

func (f *Fullrate) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": f.DeviceName+" "+f.Version,
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
		url := fmt.Sprintf(model.CVE.MainResource(), strings.ToLower(strings.ReplaceAll(fmt.Sprintf("%v %v", f.DeviceName, f.Version), " ", "%20")))
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
		f.CveList = append(f.CveList, vl.CVEID)
		totalScore += vl.BaseScore
	}

	f.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if f.CveScore > 7 {
		f.Sensibility = "HIGH"
	} else if f.CveScore >= 4 && f.CveScore <= 7 {
		f.Sensibility = "MEDIUM"
	} else if f.CveScore < 4 {
		f.Sensibility = "LOW"
	}
	f.CveList = utils.RemoveDuplicates(f.CveList)
}

func (f *Fullrate) PrintInfo() string { return model.Category.Router() + " | Fullrate" }

func (f *Fullrate) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         f.Category,
		DeviceName:       f.DeviceName,
		Version:          f.Version,
		CveList:          f.CveList,
		Sensibility:      f.Sensibility,
		CveScore:         f.CveScore,
		ExtraInformation: f.ExtraInformation,
	}
}
