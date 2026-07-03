package hp

import (
	"fmt"
	"strconv"
	"strings"
	"zspure/config"
	"zspure/config/cmd"
	"zspure/handler"
	"zspure/modules/model"
	"zspure/utils"
)

type Hp struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (a *Hp) SetCategory(category ...string) {
	a.Category = model.Category.Printer()
}

func (a *Hp) SetDeviceName(device ...string) {
	a.DeviceName = "Hp"
}

func (a *Hp) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (a *Hp) Filters(banner map[string]interface{}) bool {
	if banner["banner"] == nil {
		return false
	}
	if val, ok := banner["banner"].(string); ok {
		if strings.Contains(val, "FTP Server") && (strings.Contains(val, "HP ARPA") || strings.Contains(val, "JD FTP Server Ready") || strings.Contains(val, "The HPRC FTP dropbox system is intended for Hewlett-Packa")) {
			return true
		}
	}
	return false
}

func (a *Hp) DeviceScan(banner map[string]interface{}) bool {
	if val, ok := banner["banner"]; ok {
		bannerStr := fmt.Sprintf("%v", val)
		a.ExtraInformation.NewExtraInfo()
		if strings.Contains(bannerStr, "HP ARPA FTP Server") {
			a.ExtraInformation.SetExtraInfo("product", "HP ARPA")
			return true
		}
		if strings.Contains(bannerStr, "JD FTP Server Ready") {
			a.ExtraInformation.SetExtraInfo("product", "Jet Direct")
			return true
		}
		if strings.Contains(bannerStr, "The HPRC FTP dropbox system is intended for Hewlett-Packa") {
			a.ExtraInformation.SetExtraInfo("product", "HP HPRC")
			return true
		}
	}
	return false
}

func (a *Hp) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": a.DeviceName,
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
		url := fmt.Sprintf(model.CVE.MainResource(), "hp%20"+"printer")
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

func (a *Hp) PrintInfo() string { return model.Category.Printer() + " | Hp" }

func (a *Hp) Result() model.ModuleStructure {
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
