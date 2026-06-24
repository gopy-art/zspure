package sshservice

import (
	"fmt"
	"strconv"
	"strings"
	"zspure/handler"
	"zspure/modules/model"
	"zspure/utils"
)

type SSHService struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (s *SSHService) SetCategory(category ...string) {
	s.Category = model.Category.Service()
}

func (s *SSHService) SetDeviceName(device ...string) {
	s.DeviceName = ""
}

func (a *SSHService) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (s *SSHService) Filters(banner map[string]interface{}) bool {
	if banner["server_id"] == nil {
		return false
	}
	if val, ok := banner["server_id"].(map[string]interface{}); ok && val != nil {
		if v, okk := val["raw"]; okk && v != nil {
			return true
		}
	}
	return false
}

func (s *SSHService) DeviceScan(banner map[string]interface{}) bool {
	if val, ok := banner["server_id"].(map[string]interface{}); ok && val != nil {
		if strings.Contains(val["software"].(string), "_") {
			s.DeviceName = strings.Split(val["software"].(string), "_")[0]
		} else {
			s.DeviceName = fmt.Sprintf("%v", strings.Split(val["software"].(string), " ")[0])
		}
	}

	if val, ok := banner["server_id"].(map[string]interface{}); ok && val != nil {
		if strings.Contains(val["software"].(string), "_") {
			s.Version = strings.Split(val["software"].(string), "_")[1]
		}
	} else {
		if val, ok := banner["server_id"].(map[string]interface{}); ok && val != nil {
			s.Version = fmt.Sprintf("%v", strings.Split(val["version"].(string), " ")[0])
		}
	}

	if strings.Contains(s.Version, "p") {
		s.Version = strings.Split(s.Version, "p")[0]
	}

	return false
}

func (s *SSHService) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0
	result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
		"cve.descriptions.value": fmt.Sprintf("%v %v", s.DeviceName, s.Version),
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

func (s *SSHService) PrintInfo() string { return model.Category.Service() + " | SSH" }

func (s *SSHService) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    s.Category,
		DeviceName:  s.DeviceName,
		Version:     s.Version,
		CveList:     s.CveList,
		Sensibility: s.Sensibility,
		CveScore:    s.CveScore,
	}
}
