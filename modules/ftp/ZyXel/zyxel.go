package zyxel

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

type ZyXelRouterFTP struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (z *ZyXelRouterFTP) SetCategory(category ...string) {
	z.Category = model.Category.Router()
}

func (z *ZyXelRouterFTP) SetDeviceName(device ...string) {
	z.DeviceName = "ZyXel Router FTP"
}

func (z *ZyXelRouterFTP) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (z *ZyXelRouterFTP) Filters(banner map[string]interface{}) bool {
	re := regexp.MustCompile(`^220 P(-)?660[HDR].* FTP version ([\d.]+) ready at`)
	matches := re.FindStringSubmatch(banner["banner"].(string))
	if banner["banner"] != nil &&
		banner["banner"].(string) != "" &&
		len(matches) > 2 {
		return true
	}
	return false
}

func (z *ZyXelRouterFTP) DeviceScan(banner map[string]interface{}) bool {
	z.ExtraInformation.NewExtraInfo()
	re := regexp.MustCompile(`^220 (P-?660[^\s]+) FTP version ([\d.]+) ready at`)
	matches := re.FindStringSubmatch(banner["banner"].(string))
	if len(matches) > 2 {
		z.Version = matches[2]
		z.ExtraInformation.SetExtraInfo("product", matches[1])
		return true
	}
	return false
}

func (z *ZyXelRouterFTP) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": fmt.Sprintf("zyxel %v", z.Version),
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
			strings.ToLower(strings.ReplaceAll(fmt.Sprintf("zyxel %v", z.Version), " ", "%20")))
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

func (z *ZyXelRouterFTP) PrintInfo() string { return model.Category.Router() + " | ZyXel Router FTP" }

func (z *ZyXelRouterFTP) Result() model.ModuleStructure {
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
