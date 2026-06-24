package uclinux

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

type UClinuxServer struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (u *UClinuxServer) SetCategory(category ...string) {
	u.Category = model.Category.Service()
}

func (u *UClinuxServer) SetDeviceName(device ...string) {
	u.DeviceName = "uClinux FTP Server"
}

func (u *UClinuxServer) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (u *UClinuxServer) Filters(banner map[string]interface{}) bool {
	if banner["banner"] != nil && banner["banner"].(string) != "" && strings.Contains(banner["banner"].(string), "uClinux FTP server") {
		return true
	}
	return false
}

func (u *UClinuxServer) DeviceScan(banner map[string]interface{}) bool {
	u.ExtraInformation.NewExtraInfo()
	re := regexp.MustCompile(`\([^)]*?\s+(\d+\.\d+\.\d+)\)`)
	matches := re.FindStringSubmatch(banner["banner"].(string))
	if len(matches) > 1 {
		u.Version = matches[1]
		if strings.Contains(banner["banner"].(string), "GNU inetutils") {
			u.ExtraInformation.SetExtraInfo("product", "GNU inetutils")
		}
		return true
	}
	return false
}

func (u *UClinuxServer) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": fmt.Sprintf("uclinux %v", u.Version),
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
			strings.ToLower(strings.ReplaceAll(fmt.Sprintf("uclinux %v", u.Version), " ", "%20")))
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
		u.CveList = append(u.CveList, v.CVEID)
		totalScore += v.BaseScore
	}

	u.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if u.CveScore > 7 {
		u.Sensibility = "HIGH"
	} else if u.CveScore >= 4 && u.CveScore <= 7 {
		u.Sensibility = "MEDIUM"
	} else if u.CveScore < 4 {
		u.Sensibility = "LOW"
	}
	u.CveList = utils.RemoveDuplicates(u.CveList)
}

func (u *UClinuxServer) PrintInfo() string { return model.Category.Service() + " | uClinux FTP Server" }

func (u *UClinuxServer) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         u.Category,
		DeviceName:       u.DeviceName,
		Version:          u.Version,
		CveList:          u.CveList,
		Sensibility:      u.Sensibility,
		CveScore:         u.CveScore,
		ExtraInformation: u.ExtraInformation,
	}
}
