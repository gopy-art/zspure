package computec

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

type Computec struct {
	Category    string                `json:"dvs_category"`
	DeviceName  string                `json:"device_name"`
	Version     string                `json:"version"`
	CveList     []string              `json:"cves"`
	Sensibility string                `json:"base_severity"`
	CveScore    float64               `json:"cve_score"`
	ExtraInfo   model.ModuleExtraInfo `json:"dvs_extra"`
}

func (c *Computec) SetCategory(category ...string) {
	c.Category = model.Category.Industrial()
}

func (c *Computec) SetDeviceName(device ...string) {
	c.DeviceName = "Computec Oy"
}

func (c *Computec) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.mei_response.objects.vendor": "Computec Oy"},
	}
}

func (c *Computec) Filters(banner map[string]interface{}) bool {
	if banner["device_id"] == nil {
		return false
	}
	if val, ok := banner["mei_response"].(map[string]interface{})["objects"].(map[string]interface{})["vendor"]; ok {
		if strings.Contains(strings.ToLower(val.(string)), "computec oy") {
			return true
		}
	}
	return false
}

func (c *Computec) DeviceScan(banner map[string]interface{}) bool {
	c.ExtraInfo.NewExtraInfo()
	if val, ok := banner["mei_response"].(map[string]interface{})["objects"].(map[string]interface{})["product_code"].(string); ok && val != "" {
		c.ExtraInfo.SetExtraInfo("product", val)
	}

	if val, ok := banner["mei_response"].(map[string]interface{})["objects"].(map[string]interface{})["revision"].(string); ok && val != "" {
		c.Version = val
		return true
	}
	return false
}

func (c *Computec) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": "Computec "+c.Version,
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
		url := fmt.Sprintf(model.CVE.MainResource(), strings.ToLower(strings.ReplaceAll(fmt.Sprintf("Computec %v", c.Version), " ", "%20")))
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
		c.CveList = append(c.CveList, vl.CVEID)
		totalScore += vl.BaseScore
	}

	c.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if c.CveScore > 7 {
		c.Sensibility = "HIGH"
	} else if c.CveScore >= 4 && c.CveScore <= 7 {
		c.Sensibility = "MEDIUM"
	} else if c.CveScore < 4 {
		c.Sensibility = "LOW"
	}
	c.CveList = utils.RemoveDuplicates(c.CveList)
}

func (c *Computec) PrintInfo() string { return model.Category.Industrial() + " | Computec PLC" }

func (c *Computec) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         c.Category,
		DeviceName:       c.DeviceName,
		Version:          c.Version,
		CveList:          c.CveList,
		Sensibility:      c.Sensibility,
		CveScore:         c.CveScore,
		ExtraInformation: c.ExtraInfo,
	}
}
