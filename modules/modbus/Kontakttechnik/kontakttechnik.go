package kontakttechnik

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

type WAGOKontakttechnikGmbH struct {
	Category    string                `json:"dvs_category"`
	DeviceName  string                `json:"device_name"`
	Version     string                `json:"version"`
	CveList     []string              `json:"cves"`
	Sensibility string                `json:"base_severity"`
	CveScore    float64               `json:"cve_score"`
	ExtraInfo   model.ModuleExtraInfo `json:"dvs_extra"`
}

func (w *WAGOKontakttechnikGmbH) SetCategory(category ...string) {
	w.Category = model.Category.Industrial()
}

func (w *WAGOKontakttechnikGmbH) SetDeviceName(device ...string) {
	w.DeviceName = "WAGO Kontakttechnik GmbH"
}

func (w *WAGOKontakttechnikGmbH) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.mei_response.objects.vendor": "WAGO Kontakttechnik GmbH"},
	}
}

func (w *WAGOKontakttechnikGmbH) Filters(banner map[string]interface{}) bool {
	if banner["mei_response"] == nil {
		return false
	}
	if val, ok := banner["mei_response"].(map[string]interface{})["objects"].(map[string]interface{})["vendor"].(string); ok {
		if strings.Contains(strings.ToLower(val), "wago kontakttechnik gmbh") {
			return true
		}
	}
	return false
}

func (w *WAGOKontakttechnikGmbH) DeviceScan(banner map[string]interface{}) bool {
	w.ExtraInfo.NewExtraInfo()
	if val, ok := banner["mei_response"].(map[string]interface{})["objects"].(map[string]interface{})["product_code"].(string); ok && val != "" {
		w.ExtraInfo.SetExtraInfo("product", val)
	}

	if val, ok := banner["mei_response"].(map[string]interface{})["objects"].(map[string]interface{})["revision"].(string); ok && val != "" {
		w.Version = val
	}

	return false
}

func (w *WAGOKontakttechnikGmbH) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": fmt.Sprintf("kontakttechnik %v", w.Version),
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
			strings.ToLower(strings.ReplaceAll(fmt.Sprintf("kontakttechnik %v", w.Version), " ", "%20")))
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
		w.CveList = append(w.CveList, v.CVEID)
		totalScore += v.BaseScore
	}

	w.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if w.CveScore > 7 {
		w.Sensibility = "HIGH"
	} else if w.CveScore >= 4 && w.CveScore <= 7 {
		w.Sensibility = "MEDIUM"
	} else if w.CveScore < 4 {
		w.Sensibility = "LOW"
	}
	w.CveList = utils.RemoveDuplicates(w.CveList)
}

func (w *WAGOKontakttechnikGmbH) PrintInfo() string {
	return model.Category.Industrial() + " | WAGO Kontakttechnik GmbH"
}

func (w *WAGOKontakttechnikGmbH) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         w.Category,
		DeviceName:       w.DeviceName,
		Version:          w.Version,
		CveList:          w.CveList,
		Sensibility:      w.Sensibility,
		CveScore:         w.CveScore,
		ExtraInformation: w.ExtraInfo,
	}
}
