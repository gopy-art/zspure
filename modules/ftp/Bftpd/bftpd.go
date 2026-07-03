package bftpd

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

type Bftpd struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (b *Bftpd) SetCategory(category ...string) {
	b.Category = model.Category.Service()
}

func (b *Bftpd) SetDeviceName(device ...string) {
	b.DeviceName = "Bftpd"
}

func (b *Bftpd) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (b *Bftpd) Filters(banner map[string]interface{}) bool {
	if banner["banner"] == nil {
		return false
	}
	if val, ok := banner["banner"].(string); ok {
		if strings.Contains(val, "220 bftpd") || strings.Contains(val, "220 (bftpd)") {
			return true
		}
	}
	return false
}

func (b *Bftpd) DeviceScan(banner map[string]interface{}) bool {
	if banner["banner"] == nil {
		return false
	}
	if val, ok := banner["banner"].(string); ok {
		if strings.Contains(val, "220 bftpd") {
			b.Version = strings.Split(strings.Split(val, "220 bftpd ")[1], " at")[0]
			return true
		}
	}
	return false
}

func (b *Bftpd) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": b.DeviceName+" "+b.Version,
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
		url := fmt.Sprintf(model.CVE.MainResource(), strings.ToLower(strings.ReplaceAll(fmt.Sprintf("%v %v", b.DeviceName, b.Version), " ", "%20")))
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
		b.CveList = append(b.CveList, vl.CVEID)
		totalScore += vl.BaseScore
	}

	b.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if b.CveScore > 7 {
		b.Sensibility = "HIGH"
	} else if b.CveScore >= 4 && b.CveScore <= 7 {
		b.Sensibility = "MEDIUM"
	} else if b.CveScore < 4 {
		b.Sensibility = "LOW"
	}
	b.CveList = utils.RemoveDuplicates(b.CveList)
}

func (b *Bftpd) PrintInfo() string { return model.Category.Service() + " | Bftpd" }

func (b *Bftpd) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         b.Category,
		DeviceName:       b.DeviceName,
		Version:          b.Version,
		CveList:          b.CveList,
		Sensibility:      b.Sensibility,
		CveScore:         b.CveScore,
		ExtraInformation: b.ExtraInformation,
	}
}
