package devices

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

type ImapDevices struct {
	Category    string                `json:"dvs_category"`
	DeviceName  string                `json:"device_name"`
	Version     string                `json:"version"`
	CveList     []string              `json:"cves"`
	Sensibility string                `json:"base_severity"`
	CveScore    float64               `json:"cve_score"`
	ExtraInfo   model.ModuleExtraInfo `json:"dvs_extra"`
}

var modelType string

func (i *ImapDevices) SetCategory(category ...string) {
	i.Category = model.Category.Service()
}

func (i *ImapDevices) SetDeviceName(device ...string) {
	i.DeviceName = "IMAP Device"
}

func (i *ImapDevices) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (i *ImapDevices) Filters(banner map[string]interface{}) bool {
	if banner["banner"] == nil {
		return false
	}
	if val, ok := banner["banner"].(string); ok {
		if strings.Contains(val, "Dovecot") || strings.Contains(val, "Courier-IMAP") || strings.Contains(val, "Gimap") {
			return true
		}
	}
	return false
}

func (i *ImapDevices) DeviceScan(banner map[string]interface{}) bool {
	if val, ok := banner["banner"]; ok && val != "" {
		i.ExtraInfo.NewExtraInfo()
		bannerStr := fmt.Sprintf("%v", val)
		if strings.Contains(bannerStr, "Dovecot") {
			i.ExtraInfo.SetExtraInfo("product", "Dovecot")
			modelType = "Dovecot"
			return true
		}
		if strings.Contains(bannerStr, "Courier-IMAP") {
			i.ExtraInfo.SetExtraInfo("product", "Courier")
			modelType = "Courier-IMAP"
			return true
		}
		if strings.Contains(bannerStr, "Gimap") {
			i.ExtraInfo.SetExtraInfo("product", "IMAP")
			i.ExtraInfo.SetExtraInfo("manufacturer", "Google")
			modelType = "Gimap"
			return true
		}
	}
	return false
}

func (i *ImapDevices) CveScan(els *handler.Elastic) {
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
		url := fmt.Sprintf(model.CVE.MainResource(), modelType)
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
		i.CveList = append(i.CveList, vl.CVEID)
		totalScore += vl.BaseScore
	}

	i.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if i.CveScore > 7 {
		i.Sensibility = "HIGH"
	} else if i.CveScore >= 4 && i.CveScore <= 7 {
		i.Sensibility = "MEDIUM"
	} else if i.CveScore < 4 {
		i.Sensibility = "LOW"
	}
	i.CveList = utils.RemoveDuplicates(i.CveList)
}

func (i *ImapDevices) PrintInfo() string { return model.Category.Service() + " | Imap Devices" }

func (i *ImapDevices) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         i.Category,
		DeviceName:       i.DeviceName,
		Version:          i.Version,
		CveList:          i.CveList,
		Sensibility:      i.Sensibility,
		CveScore:         i.CveScore,
		ExtraInformation: i.ExtraInfo,
	}
}
