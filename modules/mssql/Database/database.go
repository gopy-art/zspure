package database

import (
	"fmt"
	"strconv"
	"zspure/handler"
	"zspure/modules/model"
	"zspure/utils"
)

type MsSQLDatabase struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (m *MsSQLDatabase) SetCategory(category ...string) {
	m.Category = model.Category.Database()
}

func (m *MsSQLDatabase) SetDeviceName(device ...string) {
	m.DeviceName = "MSSQL DB"
}

func (a *MsSQLDatabase) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (m *MsSQLDatabase) Filters(banner map[string]interface{}) bool {
	if banner["version"] == nil || banner["tls"] == nil {
		return false
	}
	if val, ok := banner["version"].(string); ok {
		if val != "" {
			return true
		}
	}
	return false
}

func (m *MsSQLDatabase) DeviceScan(banner map[string]interface{}) bool {
	if val, ok := banner["version"].(string); ok && val != "" {
		m.Version = val
	}

	return false
}

func (m *MsSQLDatabase) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0
	result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "or", map[string]interface{}{
		"cve.descriptions.value": fmt.Sprintf("mssql %s", m.Version),
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

func (m *MsSQLDatabase) PrintInfo() string { return model.Category.Database() + " | MSSQL DB" }

func (m *MsSQLDatabase) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    m.Category,
		DeviceName:  m.DeviceName,
		Version:     m.Version,
		CveList:     m.CveList,
		Sensibility: m.Sensibility,
		CveScore:    m.CveScore,
	}
}
