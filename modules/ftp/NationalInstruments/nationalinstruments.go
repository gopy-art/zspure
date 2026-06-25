package nationalinstruments

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

type NationalInstruments struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
}

func (n *NationalInstruments) SetCategory(category ...string) {
	n.Category = model.Category.Industrial()
}

func (n *NationalInstruments) SetDeviceName(device ...string) {
	n.DeviceName = "National Instruments"
}

func (n *NationalInstruments) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (n *NationalInstruments) Filters(banner map[string]interface{}) bool {
	if banner["banner"] != nil && banner["banner"].(string) != "" && strings.Contains(strings.ToLower(banner["banner"].(string)), strings.ToLower("National Instruments")) {
		return true
	}
	return false
}

func (n *NationalInstruments) DeviceScan(banner map[string]interface{}) bool {
	return false
}

func (n *NationalInstruments) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": fmt.Sprintf("%v", n.DeviceName),
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
			strings.ToLower(strings.ReplaceAll(fmt.Sprintf("%v", n.DeviceName), " ", "%20")))
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
		n.CveList = append(n.CveList, v.CVEID)
		totalScore += v.BaseScore
	}

	n.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if n.CveScore > 7 {
		n.Sensibility = "HIGH"
	} else if n.CveScore >= 4 && n.CveScore <= 7 {
		n.Sensibility = "MEDIUM"
	} else if n.CveScore < 4 {
		n.Sensibility = "LOW"
	}
	n.CveList = utils.RemoveDuplicates(n.CveList)
}

func (n *NationalInstruments) PrintInfo() string {
	return model.Category.Industrial() + " | National Instruments"
}

func (n *NationalInstruments) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         n.Category,
		DeviceName:       n.DeviceName,
		Version:          n.Version,
		CveList:          n.CveList,
		Sensibility:      n.Sensibility,
		CveScore:         n.CveScore,
	}
}