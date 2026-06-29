package dopra

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

type Dopra struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (d *Dopra) SetCategory(category ...string) {
	d.Category = model.Category.Network()
}

func (d *Dopra) SetDeviceName(device ...string) {
	d.DeviceName = "Dopra"
}

func (d *Dopra) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (d *Dopra) Filters(banner map[string]interface{}) bool {
	if banner["server_id"] == nil {
		return false
	}
	if val, ok := banner["server_id"].(map[string]interface{}); ok && val != nil {
		if v, okk := val["raw"].(string); okk && strings.Contains(strings.ToLower(v), "dopra") {
			return true
		}
	}
	return false
}

func (d *Dopra) DeviceScan(banner map[string]interface{}) bool {
	d.ExtraInformation.NewExtraInfo()
	if ok, result := os.DetectOperatingSystems(banner["server_id"].(map[string]interface{})["raw"].(string)); ok {
		if result.Name != "" {
			d.ExtraInformation.SetExtraInfo("operating_system", result.Name)
		}
		if result.Version != "" {
			d.ExtraInformation.SetExtraInfo("os_version", result.Version)
		}
	}

	d.ExtraInformation.SetExtraInfo("product", "Huawei Dopra")
	re := regexp.MustCompile(`DOPRA-([\d.]+)`)
	matches := re.FindStringSubmatch(banner["server_id"].(map[string]interface{})["raw"].(string))
	if len(matches) > 1 {
		d.Version = matches[1]
		return true
	}
	return false
}

func (d *Dopra) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0
	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": fmt.Sprintf("%v %v", d.DeviceName, d.Version),
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
			strings.ToLower(strings.ReplaceAll(fmt.Sprintf("%v %v", d.DeviceName, d.Version), " ", "%20")))
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
		d.CveList = append(d.CveList, v.CVEID)
		totalScore += v.BaseScore
	}

	d.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if d.CveScore > 7 {
		d.Sensibility = "HIGH"
	} else if d.CveScore >= 4 && d.CveScore <= 7 {
		d.Sensibility = "MEDIUM"
	} else if d.CveScore < 4 {
		d.Sensibility = "LOW"
	}
	d.CveList = utils.RemoveDuplicates(d.CveList)
}

func (d *Dopra) PrintInfo() string { return model.Category.Network() + " | Dopra" }

func (d *Dopra) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         d.Category,
		DeviceName:       d.DeviceName,
		Version:          d.Version,
		CveList:          d.CveList,
		Sensibility:      d.Sensibility,
		CveScore:         d.CveScore,
		ExtraInformation: d.ExtraInformation,
	}
}