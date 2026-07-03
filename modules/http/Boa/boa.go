package boa

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

type Boa struct {
	Category    string                `json:"dvs_category"`
	DeviceName  string                `json:"device_name"`
	Version     string                `json:"version"`
	CveList     []string              `json:"cves"`
	Sensibility string                `json:"base_severity"`
	CveScore    float64               `json:"cve_score"`
}

func (b *Boa) SetCategory(category ...string) {
	b.Category = model.Category.Camera()
}

func (b *Boa) SetDeviceName(device ...string) {
	b.DeviceName = "Boa"
}

func (b *Boa) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.response.headers.server": "Boa"},
	}
}

func (b *Boa) Filters(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	if val, ok := banner["response"].(map[string]interface{})["headers"].(map[string]interface{})["server"].([]any); ok {
		if strings.Contains(val[0].(string), "Boa") {
			return true
		}
	}
	return false
}

func (b *Boa) DeviceScan(banner map[string]interface{}) bool {
	if val, ok := banner["response"].(map[string]interface{})["headers"].(map[string]interface{})["server"].([]any); ok {
		if strings.Contains(strings.ToLower(val[0].(string)), "/") {
			b.Version = strings.Split(val[0].(string), "/")[1]
			return true
		}
	}

	return false
}

func (b *Boa) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": b.DeviceName+" "+b.Version,
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
		url := fmt.Sprintf(model.CVE.MainResource(), b.DeviceName+"%20"+b.Version)
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
		b.CveList = append(b.CveList, vl.CVEID)
		totalScore += vl.BaseScore
	}

	b.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if b.CveScore > 7 {
		b.Sensibility = "HIGH"
	} else if b.CveScore >= 4 && b.CveScore <= 7 {
		b.Sensibility = "MEDIUM"
	} else if b.CveScore < 4 {
		b.Sensibility = "LOW"
	}
	b.CveList = utils.RemoveDuplicates(b.CveList)
}

func (b *Boa) PrintInfo() string { return model.Category.Camera() + " | Boa" }

func (b *Boa) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         b.Category,
		DeviceName:       b.DeviceName,
		Version:          b.Version,
		CveList:          b.CveList,
		Sensibility:      b.Sensibility,
		CveScore:         b.CveScore,
	}
}
