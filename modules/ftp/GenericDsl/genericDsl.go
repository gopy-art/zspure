package genericDsl

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

type GenericDsl struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (g *GenericDsl) SetCategory(category ...string) {
	g.Category = model.Category.Router()
}

func (g *GenericDsl) SetDeviceName(device ...string) {
	g.DeviceName = "GenericDsl"
}

func (g *GenericDsl) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (g *GenericDsl) Filters(banner map[string]interface{}) bool {
	if banner["banner"] == nil {
		return false
	}
	if val, ok := banner["banner"].(string); ok {
		if strings.Contains(val, "DSL Router") && strings.Contains(val, "FTP Server") {
			return true
		}
	}
	return false
}

func (g *GenericDsl) DeviceScan(banner map[string]interface{}) bool {
	if val, ok := banner["banner"]; ok {
		bannerStr := fmt.Sprintf("%v", val)
		if strings.Contains(bannerStr, "DSL Router FTP Server") {
			versionRe := regexp.MustCompile(`(?i)Server v(\d+(?:\.\d+)*)(?:v([a-zA-Z0-9]+))? ready`)
			matches := versionRe.FindStringSubmatch(bannerStr)
			if len(matches) > 2 {
				g.Version = matches[1]
				if matches[2] != "" {
					g.ExtraInformation.NewExtraInfo()
					g.ExtraInformation.SetExtraInfo("revision", matches[2])
				}
				return true
			}
		}
	}
	return false
}

func (g *GenericDsl) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": g.DeviceName+" "+g.Version,
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
		url := fmt.Sprintf(model.CVE.MainResource(), strings.ToLower(strings.ReplaceAll(fmt.Sprintf("%v %v", g.DeviceName, g.Version), " ", "%20")))
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
		g.CveList = append(g.CveList, vl.CVEID)
		totalScore += vl.BaseScore
	}

	g.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if g.CveScore > 7 {
		g.Sensibility = "HIGH"
	} else if g.CveScore >= 4 && g.CveScore <= 7 {
		g.Sensibility = "MEDIUM"
	} else if g.CveScore < 4 {
		g.Sensibility = "LOW"
	}
	g.CveList = utils.RemoveDuplicates(g.CveList)
}

func (g *GenericDsl) PrintInfo() string { return model.Category.Router() + " | GenericDsl" }

func (g *GenericDsl) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         g.Category,
		DeviceName:       g.DeviceName,
		Version:          g.Version,
		CveList:          g.CveList,
		Sensibility:      g.Sensibility,
		CveScore:         g.CveScore,
		ExtraInformation: g.ExtraInformation,
	}
}
