package paramiko

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

type Paramiko struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (p *Paramiko) SetCategory(category ...string) {
	p.Category = model.Category.Service()
}

func (p *Paramiko) SetDeviceName(device ...string) {
	p.DeviceName = "Paramiko"
}

func (p *Paramiko) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (p *Paramiko) Filters(banner map[string]interface{}) bool {
	if banner["server_id"] == nil {
		return false
	}
	if val, ok := banner["server_id"].(map[string]interface{}); ok && val != nil {
		if v, okk := val["raw"].(string); okk && strings.Contains(strings.ToLower(v), "paramiko") {
			return true
		}
	}
	return false
}

func (p *Paramiko) DeviceScan(banner map[string]interface{}) bool {
	p.ExtraInformation.NewExtraInfo()
	if ok, result := os.DetectOperatingSystems(banner["server_id"].(map[string]interface{})["raw"].(string)); ok {
		if result.Name != "" {
			p.ExtraInformation.SetExtraInfo("operating_system", result.Name)
		}
		if result.Version != "" {
			p.ExtraInformation.SetExtraInfo("os_version", result.Version)
		}
	}

	re := regexp.MustCompile(`paramiko_([\d.]+)`)
	matches := re.FindStringSubmatch(banner["server_id"].(map[string]interface{})["raw"].(string))
	if len(matches) > 1 {
		p.Version = matches[1]
		return true
	}
	return false
}

func (p *Paramiko) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0
	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": fmt.Sprintf("%v %v", p.DeviceName, p.Version),
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
			strings.ToLower(strings.ReplaceAll(fmt.Sprintf("%v %v", p.DeviceName, p.Version), " ", "%20")))
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
		p.CveList = append(p.CveList, v.CVEID)
		totalScore += v.BaseScore
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

func (p *Paramiko) PrintInfo() string { return model.Category.Service() + " | Paramiko" }

func (p *Paramiko) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         p.Category,
		DeviceName:       p.DeviceName,
		Version:          p.Version,
		CveList:          p.CveList,
		Sensibility:      p.Sensibility,
		CveScore:         p.CveScore,
		ExtraInformation: p.ExtraInformation,
	}
}
