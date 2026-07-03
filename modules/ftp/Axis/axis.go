package axis

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

type Axis struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (a *Axis) SetCategory(category ...string) {
	a.Category = model.Category.Camera()
}

func (a *Axis) SetDeviceName(device ...string) {
	a.DeviceName = "Axis"
}

func (a *Axis) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (a *Axis) Filters(banner map[string]interface{}) bool {
	if banner["banner"] == nil {
		return false
	}
	if val, ok := banner["banner"].(string); ok {
		if strings.Contains(val, "AXIS") && (strings.Contains(val, "Network Camera") || strings.Contains(val, "Video Encoder")) {
			return true
		}
	}
	return false
}

func (a *Axis) DeviceScan(banner map[string]interface{}) bool {
	if val, ok := banner["banner"]; ok {
		bannerStr := fmt.Sprintf("%v", val)
		if strings.Contains(bannerStr, "AXIS") {
			if strings.Contains(bannerStr, "Network Camera") {
				cameraProductRe := regexp.MustCompile(`(?i)^220 AXIS (.+ Camera) \d+\.\d+`)
				matches := cameraProductRe.FindStringSubmatch(bannerStr)
				if len(matches) > 1 {
					a.ExtraInformation.NewExtraInfo()
					a.ExtraInformation.SetExtraInfo("camera_product", matches[1])
				}
			} else if strings.Contains(bannerStr, "Video Encoder") {
				encodeProductRe := regexp.MustCompile(`(?i)^220 AXIS (.+ Encoder(?: Blade)?) \d+`)
				matches := encodeProductRe.FindStringSubmatch(bannerStr)
				if len(matches) > 1 {
					a.ExtraInformation.NewExtraInfo()
					a.ExtraInformation.SetExtraInfo("encoder_product", matches[1])
				}
			}
			versionRe := regexp.MustCompile(`(?i)(?:Camera|Encoder Blade|Encoder) (\d+(?:\.\d+)*) \(`)
			matchesV := versionRe.FindStringSubmatch(bannerStr)
			if len(matchesV) > 1 {
				a.Version = (matchesV[1])
			}
			return true
		}
	}
	return false
}

func (a *Axis) CveScan(els *handler.Elastic) {
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
		url := fmt.Sprintf(model.CVE.MainResource(), "axis%20"+a.Version)
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

func (a *Axis) PrintInfo() string { return model.Category.Camera() + " | Axis" }

func (a *Axis) Result() model.ModuleStructure {
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
