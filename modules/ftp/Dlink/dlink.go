package dlink

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"zspure/config"
	"zspure/config/cmd"
	"zspure/handler"
	"zspure/modules/model"
	"zspure/utils"
)

type Dlink struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (d *Dlink) SetCategory(category ...string) {
	d.Category = model.Category.Camera()
}

func (d *Dlink) SetDeviceName(device ...string) {
	d.DeviceName = "Dlink"
}

func (a *Dlink) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (d *Dlink) Filters(banner map[string]interface{}) bool {
	if banner["banner"] == nil {
		return false
	}
	if val, ok := banner["banner"].(string); ok {
		if strings.Contains(val, "DCS") && strings.Contains(strings.ToLower(val), "ftp server") {
			return true
		}
	}
	return false
}

func (d *Dlink) DeviceScan(banner map[string]interface{}) bool {
	if banner["banner"] == nil {
		return false
	}
	if val, ok := banner["banner"].(string); ok {
		d.ExtraInformation.NewExtraInfo()
		if strings.Contains(val, "DCS") {
			product1Re := regexp.MustCompile(`(?i)^220 Welcome to (DCS-\d+[+A-Z]?) FTP`)
			matches := product1Re.FindStringSubmatch(val)
			if len(matches) > 1 {
				d.ExtraInformation.SetExtraInfo("product", matches[1])
				return true
			}
			product2Re := regexp.MustCompile(`(?i)^220 (DCS-\d+[+A-Z]?) FTP`)
			matches2 := product2Re.FindStringSubmatch(val)
			if len(matches2) > 1 {
				d.ExtraInformation.SetExtraInfo("product", matches2[1])
				return true
			}
		}
	}
	return false
}

func (d *Dlink) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": d.DeviceName,
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
		url := fmt.Sprintf(model.CVE.MainResource(), "dlink%20"+d.Version)
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
		d.CveList = append(d.CveList, vl.CVEID)
		totalScore += vl.BaseScore
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

func (d *Dlink) PrintInfo() string { return model.Category.Camera() + " | Dlink" }

func (d *Dlink) Result() model.ModuleStructure {
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
