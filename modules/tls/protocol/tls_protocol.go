package protocol

import (
	"fmt"
	"strconv"
	"strings"
	"zspure/handler"
	"zspure/modules/model"
	"zspure/utils"
)

type TLSProtocol struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (t *TLSProtocol) SetCategory(category ...string) {
	t.Category = "Protocol"
}

func (t *TLSProtocol) SetDeviceName(device ...string) {
	t.DeviceName = "TLS"
}

func (a *TLSProtocol) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (t *TLSProtocol) Filters(banner map[string]interface{}) bool {
	if banner["handshake_log"] == nil {
		return false
	}
	if _, ok := banner["handshake_log"].(map[string]interface{}); ok {
		return true
	}
	return false
}

func (t *TLSProtocol) DeviceScan(banner map[string]interface{}) bool {
	if val, ok := banner["handshake_log"].(map[string]interface{})["server_hello"].(map[string]interface{})["version"].(map[string]interface{})["name"]; ok && val != "" {
		t.Version = strings.Split(val.(string), "v")[1]
	}

	return false
}

func (t *TLSProtocol) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0
	result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
		"cve.descriptions.value": fmt.Sprintf("tls %s", t.Version),
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
		t.CveList = append(t.CveList, v.CVEID)
		totalScore += v.BaseScore
	}

	t.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if t.CveScore > 7 {
		t.Sensibility = "HIGH"
	} else if t.CveScore >= 4 && t.CveScore <= 7 {
		t.Sensibility = "MEDIUM"
	} else if t.CveScore < 4 {
		t.Sensibility = "LOW"
	}
	t.CveList = utils.RemoveDuplicates(t.CveList)
}

func (t *TLSProtocol) PrintInfo() string { return "Protocol | TLS" }

func (t *TLSProtocol) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    t.Category,
		DeviceName:  t.DeviceName,
		Version:     t.Version,
		CveList:     t.CveList,
		Sensibility: t.Sensibility,
		CveScore:    t.CveScore,
	}
}
