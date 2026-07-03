package ibm

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

type Ibm struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

var modelType string

func (i *Ibm) SetCategory(category ...string) {
	i.Category = model.Category.Electric()
}

func (i *Ibm) SetDeviceName(device ...string) {
	i.DeviceName = "Ibm"
}

func (i *Ibm) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (i *Ibm) Filters(banner map[string]interface{}) bool {
	if banner["banner"] == nil {
		return false
	}
	if val, ok := banner["banner"].(string); ok {
		if strings.Contains(val, "220-QTCP at") && strings.Contains(val, "Connection will close if idle more than") {
			return true
		}
	}
	return false
}

func (i *Ibm) DeviceScan(banner map[string]interface{}) bool {
	if banner["banner"] == nil {
		return false
	}
	i.ExtraInformation.NewExtraInfo()
	if val, ok := banner["banner"].(string); ok {
		if strings.Contains(val, "220-QTCP at") && strings.Contains(val, "Connection will close if idle more than") {
			i.ExtraInformation.SetExtraInfo("product", "Ibm IbmRC")
			modelType = "Ibm IbmRC"
			return true
		}
	}
	return false
}

func (i *Ibm) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": modelType,
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
		url := fmt.Sprintf(model.CVE.MainResource(), strings.ToLower(strings.ReplaceAll(fmt.Sprintf("%v", modelType), " ", "%20")))
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

func (i *Ibm) PrintInfo() string { return model.Category.Electric() + " | Ibm" }

func (i *Ibm) Result() model.ModuleStructure {
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
