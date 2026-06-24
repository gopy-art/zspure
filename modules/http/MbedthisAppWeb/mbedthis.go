package mbedthisappweb

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

type MbedThisAppWeb struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (m *MbedThisAppWeb) SetCategory(category ...string) {
	m.Category = model.Category.WebServer()
}

func (m *MbedThisAppWeb) SetDeviceName(device ...string) {
	m.DeviceName = "Mbedthis-Appweb"
}

func (m *MbedThisAppWeb) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.response.headers.server": "Mbedthis-Appweb"},
	}
}

func (lm *MbedThisAppWeb) Filters(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if server, sok := val.(map[string]interface{})["server"].([]any); sok {
			if convert, cok := server[0].(string); cok && strings.Contains(convert, "Mbedthis-Appweb") {
				return true
			}
		}
	}
	return false
}

func (m *MbedThisAppWeb) DeviceScan(banner map[string]interface{}) bool {
	m.ExtraInformation.NewExtraInfo()

	if strings.Contains(banner["response"].(map[string]interface{})["headers"].(map[string]interface{})["server"].([]any)[0].(string), "/") {
		m.Version = strings.Split(banner["response"].(map[string]interface{})["headers"].(map[string]interface{})["server"].([]any)[0].(string), "/")[1]
	}

	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if pl, pok := val.(map[string]interface{})["x_powered_by"].([]any); pok {
			m.ExtraInformation.SetExtraInfo("programming_language", pl[0].(string))
		}
	}
	return false
}

func (m *MbedThisAppWeb) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{"cve.descriptions.value": fmt.Sprintf("%s %s", m.DeviceName, m.Version)}))
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
		url := fmt.Sprintf(model.CVE.MainResource(), "Mbedthis-Appweb%20"+m.Version)
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

func (m *MbedThisAppWeb) PrintInfo() string { return model.Category.WebServer() + " | Mbedthis-Appweb" }

func (m *MbedThisAppWeb) Result() model.ModuleStructure {
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
