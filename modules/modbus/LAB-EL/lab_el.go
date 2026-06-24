package label

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

type Lab_EL struct {
	Category    string                `json:"dvs_category"`
	DeviceName  string                `json:"device_name"`
	Version     string                `json:"version"`
	CveList     []string              `json:"cves"`
	Sensibility string                `json:"base_severity"`
	CveScore    float64               `json:"cve_score"`
	ExtraInfo   model.ModuleExtraInfo `json:"dvs_extra"`
}

func (l *Lab_EL) SetCategory(category ...string) {
	l.Category = model.Category.Industrial()
}

func (l *Lab_EL) SetDeviceName(device ...string) {
	l.DeviceName = "LAB_EL"
}

func (l *Lab_EL) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.mei_response.objects.vendor": "LAB-EL"},
	}
}

func (l *Lab_EL) Filters(banner map[string]interface{}) bool {
	if banner["mei_response"] == nil {
		return false
	}
	if val, ok := banner["mei_response"].(map[string]interface{})["objects"].(map[string]interface{})["vendor"].(string); ok {
		if strings.Contains(strings.ToLower(val), "lab-el") {
			return true
		}
	}
	return false
}

func (l *Lab_EL) DeviceScan(banner map[string]interface{}) bool {
	l.ExtraInfo.NewExtraInfo()
	if val, ok := banner["mei_response"].(map[string]interface{})["objects"].(map[string]interface{})["product_code"].(string); ok && val != "" {
		l.ExtraInfo.SetExtraInfo("product", val)
	}

	if val, ok := banner["mei_response"].(map[string]interface{})["objects"].(map[string]interface{})["revision"].(string); ok && val != "" {
		l.Version = val
		return true
	}

	return false
}

func (l *Lab_EL) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": fmt.Sprintf("%v %v", l.DeviceName, l.Version),
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
			strings.ToLower(strings.ReplaceAll(fmt.Sprintf("%v %v", l.DeviceName, l.Version), " ", "%20")))
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
		l.CveList = append(l.CveList, v.CVEID)
		totalScore += v.BaseScore
	}

	l.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if l.CveScore > 7 {
		l.Sensibility = "HIGH"
	} else if l.CveScore >= 4 && l.CveScore <= 7 {
		l.Sensibility = "MEDIUM"
	} else if l.CveScore < 4 {
		l.Sensibility = "LOW"
	}
	l.CveList = utils.RemoveDuplicates(l.CveList)
}

func (l *Lab_EL) PrintInfo() string { return model.Category.Industrial() + " | LAB-EL" }

func (l *Lab_EL) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         l.Category,
		DeviceName:       l.DeviceName,
		Version:          l.Version,
		CveList:          l.CveList,
		Sensibility:      l.Sensibility,
		CveScore:         l.CveScore,
		ExtraInformation: l.ExtraInfo,
	}
}
