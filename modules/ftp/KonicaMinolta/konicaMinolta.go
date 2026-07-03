package konicaMinolta

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

type KonicaMinolta struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (k *KonicaMinolta) SetCategory(category ...string) {
	k.Category = model.Category.Printer()
}

func (k *KonicaMinolta) SetDeviceName(device ...string) {
	k.DeviceName = "KonicaMinolta"
}

func (k *KonicaMinolta) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (k *KonicaMinolta) Filters(banner map[string]interface{}) bool {
	if banner["banner"] == nil {
		return false
	}
	if val, ok := banner["banner"].(string); ok {
		if strings.Contains(val, "KONICA MINOLTA FTP server ready") {
			return true
		}
	}
	return false
}

func (k *KonicaMinolta) DeviceScan(banner map[string]interface{}) bool {
	return false
}

func (k *KonicaMinolta) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": k.DeviceName,
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
		url := fmt.Sprintf(model.CVE.MainResource(), strings.ToLower(strings.ReplaceAll(fmt.Sprintf("%v", k.DeviceName), " ", "%20")))
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
		k.CveList = append(k.CveList, vl.CVEID)
		totalScore += vl.BaseScore
	}

	k.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if k.CveScore > 7 {
		k.Sensibility = "HIGH"
	} else if k.CveScore >= 4 && k.CveScore <= 7 {
		k.Sensibility = "MEDIUM"
	} else if k.CveScore < 4 {
		k.Sensibility = "LOW"
	}
	k.CveList = utils.RemoveDuplicates(k.CveList)
}

func (k *KonicaMinolta) PrintInfo() string { return model.Category.Printer() + " | KonicaMinolta" }

func (k *KonicaMinolta) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         k.Category,
		DeviceName:       k.DeviceName,
		Version:          k.Version,
		CveList:          k.CveList,
		Sensibility:      k.Sensibility,
		CveScore:         k.CveScore,
		ExtraInformation: k.ExtraInformation,
	}
}
