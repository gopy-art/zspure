package database

import (
	"fmt"
	"strconv"
	"zspure/handler"
	"zspure/modules/model"
	"zspure/utils"
)

type RedisDatabase struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (r *RedisDatabase) SetCategory(category ...string) {
	r.Category = model.Category.Database()
}

func (r *RedisDatabase) SetDeviceName(device ...string) {
	r.DeviceName = "Redis DB"
}

func (a *RedisDatabase) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (r *RedisDatabase) Filters(banner map[string]interface{}) bool {
	if banner["info_response"] == nil || banner["version"] == nil || banner["ping_response"] != "PONG" {
		return false
	}
	if val, ok := banner["info_response"].(string); ok {
		if val != "" {
			return true
		}
	}
	return false
}

func (r *RedisDatabase) DeviceScan(banner map[string]interface{}) bool {
	if val, ok := banner["version"].(string); ok && val != "" {
		r.Version = val
	}

	return false
}

func (r *RedisDatabase) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0
	result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
		"cve.descriptions.value": fmt.Sprintf("redis %s", r.Version),
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
		r.CveList = append(r.CveList, v.CVEID)
		totalScore += v.BaseScore
	}

	r.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if r.CveScore > 7 {
		r.Sensibility = "HIGH"
	} else if r.CveScore >= 4 && r.CveScore <= 7 {
		r.Sensibility = "MEDIUM"
	} else if r.CveScore < 4 {
		r.Sensibility = "LOW"
	}
	r.CveList = utils.RemoveDuplicates(r.CveList)
}

func (r *RedisDatabase) PrintInfo() string { return model.Category.Database() + " | Redis DB" }

func (r *RedisDatabase) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    r.Category,
		DeviceName:  r.DeviceName,
		Version:     r.Version,
		CveList:     r.CveList,
		Sensibility: r.Sensibility,
		CveScore:    r.CveScore,
	}
}
