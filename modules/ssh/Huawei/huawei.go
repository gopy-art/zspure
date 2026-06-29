package huawei

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

type Huawei struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (h *Huawei) SetCategory(category ...string) {
	h.Category = model.Category.Network()
}

func (h *Huawei) SetDeviceName(device ...string) {
	h.DeviceName = "Huawei"
}

func (h *Huawei) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (h *Huawei) Filters(banner map[string]interface{}) bool {
	if banner["server_id"] == nil {
		return false
	}
	if val, ok := banner["server_id"].(map[string]interface{}); ok && val != nil {
		if v, okk := val["raw"].(string); okk && strings.Contains(strings.ToLower(v), "huawei") {
			return true
		}
	}
	return false
}

func (h *Huawei) DeviceScan(banner map[string]interface{}) bool {
	h.ExtraInformation.NewExtraInfo()
	if ok, result := os.DetectOperatingSystems(banner["server_id"].(map[string]interface{})["raw"].(string)); ok {
		if result.Name != "" {
			h.ExtraInformation.SetExtraInfo("operating_system", result.Name)
		}
		if result.Version != "" {
			h.ExtraInformation.SetExtraInfo("os_version", result.Version)
		}
	}

	re := regexp.MustCompile(`HUAWEI-([\d.]+)`)
	matches := re.FindStringSubmatch(banner["server_id"].(map[string]interface{})["raw"].(string))
	if len(matches) > 1 {
		h.Version = matches[1]
		return true
	}
	return false
}

func (h *Huawei) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0
	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": fmt.Sprintf("%v %v", h.DeviceName, h.Version),
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
			strings.ToLower(strings.ReplaceAll(fmt.Sprintf("%v %v", h.DeviceName, h.Version), " ", "%20")))
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
		h.CveList = append(h.CveList, v.CVEID)
		totalScore += v.BaseScore
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

func (h *Huawei) PrintInfo() string { return model.Category.Network() + " | Huawei" }

func (h *Huawei) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         h.Category,
		DeviceName:       h.DeviceName,
		Version:          h.Version,
		CveList:          h.CveList,
		Sensibility:      h.Sensibility,
		CveScore:         h.CveScore,
		ExtraInformation: h.ExtraInformation,
	}
}