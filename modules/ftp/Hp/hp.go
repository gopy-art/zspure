package hp

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

type Hp struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

var modelType string

func (h *Hp) SetCategory(category ...string) {
	h.Category = model.Category.Printer()
}

func (h *Hp) SetDeviceName(device ...string) {
	h.DeviceName = "Hp"
}

func (h *Hp) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (h *Hp) Filters(banner map[string]interface{}) bool {
	if banner["banner"] == nil {
		return false
	}
	if val, ok := banner["banner"].(string); ok {
		if strings.Contains(val, "FTP Server") && (strings.Contains(val, "HP ARPA") || strings.Contains(val, "JD FTP Server Ready") || strings.Contains(val, "The HPRC FTP dropbox system is intended for Hewlett-Packa")) {
			return true
		}
	}
	return false
}

func (h *Hp) DeviceScan(banner map[string]interface{}) bool {
	if val, ok := banner["banner"]; ok {
		bannerStr := fmt.Sprintf("%v", val)
		h.ExtraInformation.NewExtraInfo()
		if strings.Contains(bannerStr, "HP ARPA FTP Server") {
			h.ExtraInformation.SetExtraInfo("product", "HP ARPA")
			modelType = "HP ARPA"
			return true
		}
		if strings.Contains(bannerStr, "JD FTP Server Ready") {
			h.ExtraInformation.SetExtraInfo("product", "Jet Direct")
			modelType = "Jet Direct"
			return true
		}
		if strings.Contains(bannerStr, "The HPRC FTP dropbox system is intended for Hewlett-Packa") {
			h.ExtraInformation.SetExtraInfo("product", "HP HPRC")
			modelType = "HP HPRC"
			return true
		}
	}
	return false
}

func (h *Hp) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": modelType,
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
		url := fmt.Sprintf(model.CVE.MainResource(), strings.ToLower(strings.ReplaceAll(fmt.Sprintf("%v", modelType), " ", "%20")))
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

func (h *Hp) PrintInfo() string { return model.Category.Printer() + " | Hp" }

func (h *Hp) Result() model.ModuleStructure {
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
