package alcatel

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

type Alcatel struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (a *Alcatel) SetCategory(category ...string) {
	a.Category = model.Category.Router()
}

func (a *Alcatel) SetDeviceName(device ...string) {
	a.DeviceName = "Alcatel"
}

func (a *Alcatel) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (a *Alcatel) Filters(banner map[string]interface{}) bool {
	if banner["banner"] == nil {
		return false
	}
	if val, ok := banner["banner"].(string); ok {
		if strings.Contains(val, "FTP server") &&
			(strings.Contains(val, "Alcatel") || strings.Contains(val, "AOS")) &&
			!strings.Contains(val, "Network Management Card AOS") {
			return true
		}
	}
	return false
}

func (a *Alcatel) DeviceScan(banner map[string]interface{}) bool {
	if val, ok := banner["banner"]; ok {
		bannerStr := fmt.Sprintf("%v", val)
		if strings.Contains(bannerStr, "ALCATEL") {
			version := strings.Split(strings.Split(bannerStr, "ALCATEL")[1], "Copyright")[0]
			if strings.Contains(version, " \r\n220") {
				version = strings.Split(version, " \r\n220")[0]
			}
			a.Version = "ALCATEL" + version
			if strings.Contains(bannerStr, "220-TiMOS-") {
				a.ExtraInformation.NewExtraInfo()
				osRe := regexp.MustCompile(`220-(TiMOS-[^-]+)-(\d+\.\d+\.(\w\d)?)`)
				matchesOs := osRe.FindStringSubmatch(bannerStr)
				if len(matchesOs) > 1 {
					a.ExtraInformation.SetExtraInfo("os", matchesOs[1])
				}
				osVersionRe := regexp.MustCompile(`220-TiMOS-[^-]+-(\d+\.\d+\.(\w\d)?)`)
				matches := osVersionRe.FindStringSubmatch(bannerStr)
				if len(matches) > 1 {
					a.ExtraInformation.SetExtraInfo("os_version", matches[1])
				}
			}
			return true
		}
	}
	return false
}

func (a *Alcatel) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": a.Version,
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
		url := fmt.Sprintf(model.CVE.MainResource(), strings.ToLower(strings.ReplaceAll(fmt.Sprintf("%v", a.Version), " ", "%20")))
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
		a.CveList = append(a.CveList, vl.CVEID)
		totalScore += vl.BaseScore
	}

	a.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if a.CveScore > 7 {
		a.Sensibility = "HIGH"
	} else if a.CveScore >= 4 && a.CveScore <= 7 {
		a.Sensibility = "MEDIUM"
	} else if a.CveScore < 4 {
		a.Sensibility = "LOW"
	}
	a.CveList = utils.RemoveDuplicates(a.CveList)
}

func (a *Alcatel) PrintInfo() string { return model.Category.Router() + " | Alcatel" }

func (a *Alcatel) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         a.Category,
		DeviceName:       a.DeviceName,
		Version:          a.Version,
		CveList:          a.CveList,
		Sensibility:      a.Sensibility,
		CveScore:         a.CveScore,
		ExtraInformation: a.ExtraInformation,
	}
}
