package kebi

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

type Kebi struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (k *Kebi) SetCategory(category ...string) {
	k.Category = model.Category.Service()
}

func (k *Kebi) SetDeviceName(device ...string) {
	k.DeviceName = "Kebi"
}

func (k *Kebi) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (k *Kebi) Filters(banner map[string]interface{}) bool {
	if banner["banner"] == nil {
		return false
	}
	if val, ok := banner["banner"].(string); ok {
		if strings.Contains(val, "Kebi FTP Server") {
			return true
		}
	}
	return false
}

func (k *Kebi) DeviceScan(banner map[string]interface{}) bool {
	if val, ok := banner["banner"]; ok {
		k.ExtraInformation.NewExtraInfo()
		bannerStr := fmt.Sprintf("%v", val)
		if strings.Contains(bannerStr, "Kebi FTP Server") {
			versionRe := regexp.MustCompile(`(?i)\(Version (\d+(?:\.\d+)*)\)`)
			matches := versionRe.FindStringSubmatch(bannerStr)
			if len(matches) > 1 {
				k.Version = matches[1]
			}
			k.ExtraInformation.SetExtraInfo("product", "Kebi Ftpd")
			return true
		}
	}
	return false
}

func (k *Kebi) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": k.DeviceName+" "+k.Version,
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
		url := fmt.Sprintf(model.CVE.MainResource(), strings.ToLower(strings.ReplaceAll(fmt.Sprintf("%v %v", k.DeviceName, k.Version), " ", "%20")))
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
		k.CveList = append(k.CveList, vl.CVEID)
		totalScore += vl.BaseScore
	}

	k.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if k.CveScore > 7 {
		k.Sensibility = "HIGH"
	} else if k.CveScore >= 4 && k.CveScore <= 7 {
		k.Sensibility = "MEDIUM"
	} else if k.CveScore < 4 {
		k.Sensibility = "LOW"
	}
	k.CveList = utils.RemoveDuplicates(k.CveList)
}

func (k *Kebi) PrintInfo() string { return model.Category.Service() + " | Kebi" }

func (k *Kebi) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         k.Category,
		DeviceName:       k.DeviceName,
		Version:          k.Version,
		CveList:          k.CveList,
		Sensibility:      k.Sensibility,
		CveScore:         k.CveScore,
		ExtraInformation: k.ExtraInformation,
	}
}
