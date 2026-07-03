package ecosense

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

type Ecosense struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (e *Ecosense) SetCategory(category ...string) {
	e.Category = model.Category.Camera()
}

func (e *Ecosense) SetDeviceName(device ...string) {
	e.DeviceName = "Ecosense"
}

func (e *Ecosense) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (e *Ecosense) Filters(banner map[string]interface{}) bool {
	if banner["banner"] == nil {
		return false
	}
	if val, ok := banner["banner"].(string); ok {
		if strings.Contains(val, "ADH FTP SERVER READY") {
			return true
		}
	}
	return false
}

func (e *Ecosense) DeviceScan(banner map[string]interface{}) bool {
	return false
}

func (e *Ecosense) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": e.DeviceName,
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
		url := fmt.Sprintf(model.CVE.MainResource(), strings.ToLower(strings.ReplaceAll(fmt.Sprintf("%v", e.DeviceName), " ", "%20")))
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
		e.CveList = append(e.CveList, vl.CVEID)
		totalScore += vl.BaseScore
	}

	e.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if e.CveScore > 7 {
		e.Sensibility = "HIGH"
	} else if e.CveScore >= 4 && e.CveScore <= 7 {
		e.Sensibility = "MEDIUM"
	} else if e.CveScore < 4 {
		e.Sensibility = "LOW"
	}
	e.CveList = utils.RemoveDuplicates(e.CveList)
}

func (e *Ecosense) PrintInfo() string { return model.Category.Camera() + " | Ecosense" }

func (e *Ecosense) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         e.Category,
		DeviceName:       e.DeviceName,
		Version:          e.Version,
		CveList:          e.CveList,
		Sensibility:      e.Sensibility,
		CveScore:         e.CveScore,
		ExtraInformation: e.ExtraInformation,
	}
}
