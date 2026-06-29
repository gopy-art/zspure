package cisco

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"zspure/config"
	"zspure/config/cmd"
	"zspure/handler"
	"zspure/modules/model"
	"zspure/modules/ssh/os"
	"zspure/utils"
)

type Cisco struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (c *Cisco) SetCategory(category ...string) {
	c.Category = model.Category.Router()
}

func (c *Cisco) SetDeviceName(device ...string) {
	c.DeviceName = "Cisco"
}

func (c *Cisco) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (c *Cisco) Filters(banner map[string]interface{}) bool {
	if banner["server_id"] == nil {
		return false
	}
	if val, ok := banner["server_id"].(map[string]interface{}); ok && val != nil {
		if v, okk := val["raw"].(string); okk && strings.Contains(strings.ToLower(v), "cisco") {
			return true
		}
	}
	return false
}

func (c *Cisco) DeviceScan(banner map[string]interface{}) bool {
	c.ExtraInformation.NewExtraInfo()
	if ok, result := os.DetectOperatingSystems(banner["server_id"].(map[string]interface{})["raw"].(string)); ok {
		if result.Name != "" {
			c.ExtraInformation.SetExtraInfo("operating_system", result.Name)
		}
		if result.Version != "" {
			c.ExtraInformation.SetExtraInfo("os_version", result.Version)
		}
	}

	c.ExtraInformation.SetExtraInfo("product", "Cisco Router")
	re := regexp.MustCompile(`Cisco-([\d.]+)`)
	matches := re.FindStringSubmatch(banner["server_id"].(map[string]interface{})["raw"].(string))
	if len(matches) > 1 {
		c.Version = matches[1]
		return true
	}
	return false
}

func (c *Cisco) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0
	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": fmt.Sprintf("%v %v", c.DeviceName, c.Version),
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
			strings.ToLower(strings.ReplaceAll(fmt.Sprintf("%v %v", c.DeviceName, c.Version), " ", "%20")))
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
		c.CveList = append(c.CveList, v.CVEID)
		totalScore += v.BaseScore
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

func (c *Cisco) PrintInfo() string { return model.Category.Router() + " | Cisco" }

func (c *Cisco) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         c.Category,
		DeviceName:       c.DeviceName,
		Version:          c.Version,
		CveList:          c.CveList,
		Sensibility:      c.Sensibility,
		CveScore:         c.CveScore,
		ExtraInformation: c.ExtraInformation,
	}
}