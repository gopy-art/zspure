package devices

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

type SmtpDevices struct {
	Category    string                `json:"dvs_category"`
	DeviceName  string                `json:"device_name"`
	Version     string                `json:"version"`
	CveList     []string              `json:"cves"`
	Sensibility string                `json:"base_severity"`
	CveScore    float64               `json:"cve_score"`
	ExtraInfo   model.ModuleExtraInfo `json:"dvs_extra"`
}

var modelType string

func (s *SmtpDevices) SetCategory(category ...string) {
	s.Category = model.Category.Service()
}

func (s *SmtpDevices) SetDeviceName(device ...string) {
	s.DeviceName = "SMTP Devices"
}

func (s *SmtpDevices) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (s *SmtpDevices) Filters(banner map[string]interface{}) bool {
	if banner["banner"] == nil {
		return false
	}
	if val, ok := banner["banner"]; ok {
		bannerStr := fmt.Sprintf("%v", val)
		if strings.Contains(bannerStr, "Postfix") || strings.Contains(bannerStr, "Sendmail") || strings.Contains(bannerStr, "Exim") || strings.Contains(bannerStr, "gsmtp") {
			return true
		}
	}
	return false
}

func (s *SmtpDevices) DeviceScan(banner map[string]interface{}) bool {
	if val, ok := banner["banner"]; ok && val != "" {
		s.ExtraInfo.NewExtraInfo()
		bannerStr := fmt.Sprintf("%v", val)
		if strings.Contains(bannerStr, "Postfix") {
			s.ExtraInfo.SetExtraInfo("product", "Postfix")
			modelType = "Postfix"
			return true
		}
		if strings.Contains(bannerStr, "Sendmail") {
			s.ExtraInfo.SetExtraInfo("product", "Sendmail")
			modelType = "Sendmail"
			return true
		}
		if strings.Contains(bannerStr, "Exim") {
			s.ExtraInfo.SetExtraInfo("product", "Exim")
			modelType = "Exim"
			re := regexp.MustCompile(`Exim\s+([\d.]+)`)
			matches := re.FindStringSubmatch(bannerStr)
			if len(matches) > 1 {
				s.ExtraInfo.SetExtraInfo("product_version", matches[1])
			}
			return true
		}
		if strings.Contains(bannerStr, "gsmtp") {
			s.ExtraInfo.SetExtraInfo("product", "gsmtp")
			s.ExtraInfo.SetExtraInfo("manufacturer", "Google")
			modelType = "gsmtp"
			return true
		}
	}
	return false
}

func (s *SmtpDevices) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": modelType,
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
		url := fmt.Sprintf(model.CVE.MainResource(), modelType)
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
		s.CveList = append(s.CveList, vl.CVEID)
		totalScore += vl.BaseScore
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

func (s *SmtpDevices) PrintInfo() string { return model.Category.Service() + " | Smtp Devices" }

func (s *SmtpDevices) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         s.Category,
		DeviceName:       s.DeviceName,
		Version:          s.Version,
		CveList:          s.CveList,
		Sensibility:      s.Sensibility,
		CveScore:         s.CveScore,
		ExtraInformation: s.ExtraInfo,
	}
}
