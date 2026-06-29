package mpssh

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

type MPSSH struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (m *MPSSH) SetCategory(category ...string) {
	m.Category = model.Category.Server()
}

func (m *MPSSH) SetDeviceName(device ...string) {
	m.DeviceName = "HP"
}

func (m *MPSSH) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (m *MPSSH) Filters(banner map[string]interface{}) bool {
	if banner["server_id"] == nil {
		return false
	}
	if val, ok := banner["server_id"].(map[string]interface{}); ok && val != nil {
		if v, okk := val["raw"].(string); okk && strings.Contains(strings.ToLower(v), "mpssh") {
			return true
		}
	}
	return false
}

func (m *MPSSH) DeviceScan(banner map[string]interface{}) bool {
	m.ExtraInformation.NewExtraInfo()
	if ok, result := os.DetectOperatingSystems(banner["server_id"].(map[string]interface{})["raw"].(string)); ok {
		if result.Name != "" {
			m.ExtraInformation.SetExtraInfo("operating_system", result.Name)
		}
		if result.Version != "" {
			m.ExtraInformation.SetExtraInfo("os_version", result.Version)
		}
	}

	m.ExtraInformation.SetExtraInfo("product", "Integrated Lights Out (iLO)")
	m.ExtraInformation.SetExtraInfo("device_type", "Server Management")
	re := regexp.MustCompile(`mpSSH_([\d.]+)`)
	matches := re.FindStringSubmatch(banner["server_id"].(map[string]interface{})["raw"].(string))
	if len(matches) > 1 {
		m.Version = matches[1]
		return true
	}
	return false
}

func (m *MPSSH) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0
	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": fmt.Sprintf("%v %v", m.DeviceName, m.Version),
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
			strings.ToLower(strings.ReplaceAll(fmt.Sprintf("%v %v", m.DeviceName, m.Version), " ", "%20")))
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
		m.CveList = append(m.CveList, v.CVEID)
		totalScore += v.BaseScore
	}

	m.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if m.CveScore > 7 {
		m.Sensibility = "HIGH"
	} else if m.CveScore >= 4 && m.CveScore <= 7 {
		m.Sensibility = "MEDIUM"
	} else if m.CveScore < 4 {
		m.Sensibility = "LOW"
	}
	m.CveList = utils.RemoveDuplicates(m.CveList)
}

func (m *MPSSH) PrintInfo() string { return model.Category.Server() + " | MPSSH" }

func (m *MPSSH) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         m.Category,
		DeviceName:       m.DeviceName,
		Version:          m.Version,
		CveList:          m.CveList,
		Sensibility:      m.Sensibility,
		CveScore:         m.CveScore,
		ExtraInformation: m.ExtraInformation,
	}
}