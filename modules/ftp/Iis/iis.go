package iis

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

type Iis struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (i *Iis) SetCategory(category ...string) {
	i.Category = model.Category.Service()
}

func (i *Iis) SetDeviceName(device ...string) {
	i.DeviceName = "Iis"
}

func (i *Iis) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (i *Iis) Filters(banner map[string]interface{}) bool {
	if banner["banner"] == nil {
		return false
	}
	if val, ok := banner["banner"].(string); ok {
		if strings.Contains(val, "Microsoft FTP Service") {
			return true
		}
	}
	return false
}

func (i *Iis) DeviceScan(banner map[string]interface{}) bool {
	if banner["banner"] == nil {
		return false
	}
	i.ExtraInformation.NewExtraInfo()
	if val, ok := banner["banner"].(string); ok {
		if strings.Contains(val, "Microsoft FTP Service") {
			i.ExtraInformation.SetExtraInfo("product", "IIS")
			i.ExtraInformation.SetExtraInfo("os", "Windows")
			return true
		}
	}
	return false
}

func (i *Iis) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": i.DeviceName,
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
		url := fmt.Sprintf(model.CVE.MainResource(), "iis")
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

func (i *Iis) PrintInfo() string { return model.Category.Service() + " | Iis" }

func (i *Iis) Result() model.ModuleStructure {
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
