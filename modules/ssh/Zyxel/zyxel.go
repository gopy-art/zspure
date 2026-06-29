package zyxel

import (
	"fmt"
	"strconv"
	"strings"
	"zspure/config"
	"zspure/config/cmd"
	"zspure/handler"
	"zspure/modules/model"
	"zspure/modules/ssh/os"
	"zspure/utils"
)

type Zyxel struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (z *Zyxel) SetCategory(category ...string) {
	z.Category = model.Category.Network()
}

func (z *Zyxel) SetDeviceName(device ...string) {
	z.DeviceName = "Zyxel"
}

func (z *Zyxel) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (z *Zyxel) Filters(banner map[string]interface{}) bool {
	if banner["server_id"] == nil {
		return false
	}
	if val, ok := banner["server_id"].(map[string]interface{}); ok && val != nil {
		if v, okk := val["raw"].(string); okk && strings.Contains(strings.ToLower(v), "zyxel") {
			return true
		}
	}
	return false
}

func (z *Zyxel) DeviceScan(banner map[string]interface{}) bool {
	z.ExtraInformation.NewExtraInfo()
	if ok, result := os.DetectOperatingSystems(banner["server_id"].(map[string]interface{})["raw"].(string)); ok {
		if result.Name != "" {
			z.ExtraInformation.SetExtraInfo("operating_system", result.Name)
		}
		if result.Version != "" {
			z.ExtraInformation.SetExtraInfo("os_version", result.Version)
		}
	}
	return false
}

func (z *Zyxel) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0
	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": fmt.Sprintf("Zyxel"),
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
			strings.ToLower(strings.ReplaceAll(fmt.Sprintf("Zyxel"), " ", "%20")))
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
		z.CveList = append(z.CveList, v.CVEID)
		totalScore += v.BaseScore
	}

	z.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if z.CveScore > 7 {
		z.Sensibility = "HIGH"
	} else if z.CveScore >= 4 && z.CveScore <= 7 {
		z.Sensibility = "MEDIUM"
	} else if z.CveScore < 4 {
		z.Sensibility = "LOW"
	}
	z.CveList = utils.RemoveDuplicates(z.CveList)
}

func (z *Zyxel) PrintInfo() string { return model.Category.Network() + " | Zyxel" }

func (z *Zyxel) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         z.Category,
		DeviceName:       z.DeviceName,
		Version:          z.Version,
		CveList:          z.CveList,
		Sensibility:      z.Sensibility,
		CveScore:         z.CveScore,
		ExtraInformation: z.ExtraInformation,
	}
}
