package devices

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

type Pop3Devices struct {
	Category    string                `json:"dvs_category"`
	DeviceName  string                `json:"device_name"`
	Version     string                `json:"version"`
	CveList     []string              `json:"cves"`
	Sensibility string                `json:"base_severity"`
	CveScore    float64               `json:"cve_score"`
	ExtraInfo   model.ModuleExtraInfo `json:"dvs_extra"`
}

var modelType string

func (p *Pop3Devices) SetCategory(category ...string) {
	p.Category = model.Category.Service()
}

func (p *Pop3Devices) SetDeviceName(device ...string) {
	p.DeviceName = "POP3 Devices"
}

func (p *Pop3Devices) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (p *Pop3Devices) Filters(banner map[string]interface{}) bool {
	if banner["banner"] == nil {
		return false
	}
	if val, ok := banner["banner"].(string); ok {
		if strings.Contains(val, "Dovecot") || strings.Contains(val, "MailEnable") || strings.Contains(val, "Gpop") {
			return true
		}
	}
	return false
}

func (p *Pop3Devices) DeviceScan(banner map[string]interface{}) bool {
	if val, ok := banner["banner"]; ok && val != "" {
		p.ExtraInfo.NewExtraInfo()
		bannerStr := fmt.Sprintf("%v", val)
		if strings.Contains(bannerStr, "Dovecot") {
			p.ExtraInfo.SetExtraInfo("product", "Dovecot")
			modelType = "Dovecot"
			return true
		}
		if strings.Contains(bannerStr, "MailEnable") {
			p.ExtraInfo.SetExtraInfo("product", "MailEnable")
			modelType = "MailEnable"
			return true
		}
		if strings.Contains(bannerStr, "Gpop") {
			p.ExtraInfo.SetExtraInfo("product", "POP3")
			p.ExtraInfo.SetExtraInfo("manufacturer", "Google")
			modelType = "Gpop"
			return true
		}
	}
	return false
}

func (p *Pop3Devices) CveScan(els *handler.Elastic) {
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
		p.CveList = append(p.CveList, vl.CVEID)
		totalScore += vl.BaseScore
	}

	p.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if p.CveScore > 7 {
		p.Sensibility = "HIGH"
	} else if p.CveScore >= 4 && p.CveScore <= 7 {
		p.Sensibility = "MEDIUM"
	} else if p.CveScore < 4 {
		p.Sensibility = "LOW"
	}
	p.CveList = utils.RemoveDuplicates(p.CveList)
}

func (p *Pop3Devices) PrintInfo() string { return model.Category.Service() + " | POP3 Devices" }

func (p *Pop3Devices) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         p.Category,
		DeviceName:       p.DeviceName,
		Version:          p.Version,
		CveList:          p.CveList,
		Sensibility:      p.Sensibility,
		CveScore:         p.CveScore,
		ExtraInformation: p.ExtraInfo,
	}
}
