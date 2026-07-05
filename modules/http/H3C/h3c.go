package h3c

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

type H3C struct {
	Category    string                `json:"dvs_category"`
	DeviceName  string                `json:"device_name"`
	Version     string                `json:"version"`
	CveList     []string              `json:"cves"`
	Sensibility string                `json:"base_severity"`
	CveScore    float64               `json:"cve_score"`
	ExtraInfo   model.ModuleExtraInfo `json:"dvs_extra"`
}

var modelType string

func (h *H3C) SetCategory(category ...string) {
	h.Category = model.Category.Router()
}

func (h *H3C) SetDeviceName(device ...string) {
	h.DeviceName = "H3C"
}

func (h *H3C) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.response.headers.www_authenticate": "h3c"},
	}
}

func (h *H3C) Filters(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	if val, ok := banner["response"].(map[string]interface{})["headers"].(map[string]interface{}); ok && len(val) > 0 {
		if strings.Contains(strings.ToLower(fmt.Sprintf("%v", val)), "basic realm=\"h3c") {
			if body, ok := banner["response"].(map[string]interface{})["body"].(string); ok {
				if body == "" {
					return true
				} else if !strings.Contains(body, "<html>") && !strings.Contains(body, "</html>") {
					return true
				} else {
					return (len(body) < 100)
				}
			} else {
				return true
			}
		}
	}
	return false
}

func (h *H3C) DeviceScan(banner map[string]interface{}) bool {
	h.ExtraInfo.NewExtraInfo()
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		re := regexp.MustCompile(`H3C\s+([A-Za-z0-9]+)`)
		matches := re.FindStringSubmatch(fmt.Sprintf("%v", val))
		if len(matches) > 1 {
			h.ExtraInfo.SetExtraInfo("product", matches[1])
			modelType = matches[1]
			return true
		}
	}
	return false
}

func (h *H3C) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": h.DeviceName + " " + modelType,
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
		url := fmt.Sprintf(model.CVE.MainResource(), h.DeviceName+"%20"+modelType)
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
		h.CveList = append(h.CveList, vl.CVEID)
		totalScore += vl.BaseScore
	}

	h.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if h.CveScore > 7 {
		h.Sensibility = "HIGH"
	} else if h.CveScore >= 4 && h.CveScore <= 7 {
		h.Sensibility = "MEDIUM"
	} else if h.CveScore < 4 {
		h.Sensibility = "LOW"
	}
	h.CveList = utils.RemoveDuplicates(h.CveList)
}

func (h *H3C) PrintInfo() string { return model.Category.Router() + " | H3C" }

func (h *H3C) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         h.Category,
		DeviceName:       h.DeviceName,
		Version:          h.Version,
		CveList:          h.CveList,
		Sensibility:      h.Sensibility,
		CveScore:         h.CveScore,
		ExtraInformation: h.ExtraInfo,
	}
}
