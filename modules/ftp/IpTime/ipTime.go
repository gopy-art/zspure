package ipTime

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

type IpTime struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (i *IpTime) SetCategory(category ...string) {
	i.Category = model.Category.NetworkStorage()
}

func (i *IpTime) SetDeviceName(device ...string) {
	i.DeviceName = "IpTime"
}

func (i *IpTime) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (i *IpTime) Filters(banner map[string]interface{}) bool {
	if banner["banner"] == nil {
		return false
	}
	if val, ok := banner["banner"].(string); ok {
		if strings.Contains(val, "220 ipTIME_FTPD") && strings.Contains(val, "Server") {
			return true
		}
	}
	return false
}

func (i *IpTime) DeviceScan(banner map[string]interface{}) bool {
	if val, ok := banner["banner"]; ok {
		bannerStr := fmt.Sprintf("%v", val)
		if strings.Contains(bannerStr, "220 ipTIME_FTPD") {
			i.ExtraInformation.NewExtraInfo()
			versionRe := regexp.MustCompile(`(?i)^220 ipTIME_FTPD (\d+\.\d+\.\d+)([a-z])? Server`)
			matches := versionRe.FindStringSubmatch(bannerStr)
			if len(matches) > 1 {
				i.Version = matches[1]
				if len(matches) > 2 {
					i.ExtraInformation.SetExtraInfo("reversion", matches[2])
				}
			}
			i.ExtraInformation.SetExtraInfo("product", "ipTIME_FTPD")
			return true
		}
	}
	return false
}

func (i *IpTime) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": i.DeviceName+" "+i.Version,
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
		url := fmt.Sprintf(model.CVE.MainResource(), strings.ToLower(strings.ReplaceAll(fmt.Sprintf("%v %v", i.DeviceName, i.Version), " ", "%20")))
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
		i.CveList = append(i.CveList, vl.CVEID)
		totalScore += vl.BaseScore
	}

	i.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if i.CveScore > 7 {
		i.Sensibility = "HIGH"
	} else if i.CveScore >= 4 && i.CveScore <= 7 {
		i.Sensibility = "MEDIUM"
	} else if i.CveScore < 4 {
		i.Sensibility = "LOW"
	}
	i.CveList = utils.RemoveDuplicates(i.CveList)
}

func (i *IpTime) PrintInfo() string { return model.Category.NetworkStorage() + " | IpTime" }

func (i *IpTime) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         i.Category,
		DeviceName:       i.DeviceName,
		Version:          i.Version,
		CveList:          i.CveList,
		Sensibility:      i.Sensibility,
		CveScore:         i.CveScore,
		ExtraInformation: i.ExtraInformation,
	}
}
