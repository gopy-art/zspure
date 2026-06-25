package seagate

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

type Seagate struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (s *Seagate) SetCategory(category ...string) {
	s.Category = model.Category.NetworkStorage()
}

func (s *Seagate) SetDeviceName(device ...string) {
	s.DeviceName = "Seagate"
}

func (s *Seagate) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (s *Seagate) Filters(banner map[string]interface{}) bool {
	if banner["banner"] != nil && 
		banner["banner"].(string) != "" && 
		(strings.Contains(strings.ToLower(banner["banner"].(string)), strings.ToLower("220 Welcome to Seagate")) ||
		strings.Contains(strings.ToLower(banner["banner"].(string)), strings.ToLower("220 Seagate"))) {
		return true
	}
	return false
}

func (s *Seagate) DeviceScan(banner map[string]interface{}) bool {
	s.ExtraInformation.NewExtraInfo()
	if strings.Contains(strings.ToLower(banner["banner"].(string)), strings.ToLower("Seagate Central Shared")) {
		s.ExtraInformation.SetExtraInfo("product", "Seagate Central")
	}
	return false
}

func (s *Seagate) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": fmt.Sprintf("%v", s.DeviceName),
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
			strings.ToLower(strings.ReplaceAll(fmt.Sprintf("%v", s.DeviceName), " ", "%20")))
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
		s.CveList = append(s.CveList, v.CVEID)
		totalScore += v.BaseScore
	}

	s.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if s.CveScore > 7 {
		s.Sensibility = "HIGH"
	} else if s.CveScore >= 4 && s.CveScore <= 7 {
		s.Sensibility = "MEDIUM"
	} else if s.CveScore < 4 {
		s.Sensibility = "LOW"
	}
	s.CveList = utils.RemoveDuplicates(s.CveList)
}

func (s *Seagate) PrintInfo() string {
	return model.Category.NetworkStorage() + " | Seagate"
}

func (s *Seagate) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         s.Category,
		DeviceName:       s.DeviceName,
		Version:          s.Version,
		CveList:          s.CveList,
		Sensibility:      s.Sensibility,
		CveScore:         s.CveScore,
		ExtraInformation: s.ExtraInformation,
	}
}