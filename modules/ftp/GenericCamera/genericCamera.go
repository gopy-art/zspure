package genericCamera

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

type GenericCamera struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (a *GenericCamera) SetCategory(category ...string) {
	a.Category = model.Category.Camera()
}

func (a *GenericCamera) SetDeviceName(device ...string) {
	a.DeviceName = "Generic Camera"
}

func (a *GenericCamera) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (a *GenericCamera) Filters(banner map[string]interface{}) bool {
	if banner["banner"] == nil {
		return false
	}
	if val, ok := banner["banner"].(string); ok {
		if strings.Contains(val, "Network-Camera") && strings.Contains(val, "FTP server") {
			return true
		}
	}
	return false
}

func (a *GenericCamera) DeviceScan(banner map[string]interface{}) bool {
	if val, ok := banner["banner"]; ok {
		bannerStr := fmt.Sprintf("%v", val)
		if strings.Contains(bannerStr, "220 Network-Camera FTP server") {
			reRersionRe := regexp.MustCompile(`(?i)^220 Network-Camera FTP server \((.*)\) ready`)
			matches := reRersionRe.FindStringSubmatch(bannerStr)
			if len(matches) < 2 {
				return false
			}
			version := matches[1]
			a.ExtraInformation.NewExtraInfo()
			if strings.HasPrefix(matches[1], "Version") {
				parts := strings.Split(version, "/")
				a.ExtraInformation.SetExtraInfo("product", parts[len(parts)-1])
				firstPart := strings.SplitN(parts[0], " ", 2)
				if len(firstPart) == 2 {
					version = firstPart[1]
				}
				a.Version = version
				return true
			} else if strings.HasPrefix(matches[1], "GNU") {
				parts := strings.Fields(version)
				if len(parts) >= 2 {
					a.ExtraInformation.SetExtraInfo("product", strings.Join(parts[:2], " "))
				}
				if len(parts) > 2 {
					version = strings.Join(parts[2:], " ")
				}
				a.Version = version
				return true
			}
		}
	}
	return false
}

func (a *GenericCamera) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": a.DeviceName,
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
		url := fmt.Sprintf(model.CVE.MainResource(), "genericCamera%20"+a.Version)
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
		a.CveList = append(a.CveList, vl.CVEID)
		totalScore += vl.BaseScore
	}

	a.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if a.CveScore > 7 {
		a.Sensibility = "HIGH"
	} else if a.CveScore >= 4 && a.CveScore <= 7 {
		a.Sensibility = "MEDIUM"
	} else if a.CveScore < 4 {
		a.Sensibility = "LOW"
	}
	a.CveList = utils.RemoveDuplicates(a.CveList)
}

func (a *GenericCamera) PrintInfo() string { return model.Category.Camera() + " | Generic Camera" }

func (a *GenericCamera) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         a.Category,
		DeviceName:       a.DeviceName,
		Version:          a.Version,
		CveList:          a.CveList,
		Sensibility:      a.Sensibility,
		CveScore:         a.CveScore,
		ExtraInformation: a.ExtraInformation,
	}
}
