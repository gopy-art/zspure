package qnapturbo

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

type QnapTurboNas struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (o *QnapTurboNas) SetCategory(category ...string) {
	o.Category = model.Category.NetworkStorage()
}

func (o *QnapTurboNas) SetDeviceName(device ...string) {
	o.DeviceName = "Qnap Turbo Station"
}

func (o *QnapTurboNas) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (o *QnapTurboNas) Filters(banner map[string]interface{}) bool {
	if banner["banner"] != nil && banner["banner"].(string) != "" && strings.Contains(strings.ToLower(banner["banner"].(string)), strings.ToLower("NASFTPD Turbo station")) {
		return true
	}
	return false
}

func (o *QnapTurboNas) DeviceScan(banner map[string]interface{}) bool {
	re := regexp.MustCompile(`NASFTPD Turbo station\s+([\d.]+[a-z]*)`)
	matches := re.FindStringSubmatch(banner["banner"].(string))
	if len(matches) > 1 {
		o.Version = matches[1]
		return false
	}
	return false
}

func (o *QnapTurboNas) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": fmt.Sprintf("%v %v", o.DeviceName, o.Version),
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
			strings.ToLower(strings.ReplaceAll(fmt.Sprintf("%v %v", o.DeviceName, o.Version), " ", "%20")))
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
		o.CveList = append(o.CveList, v.CVEID)
		totalScore += v.BaseScore
	}

	o.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if o.CveScore > 7 {
		o.Sensibility = "HIGH"
	} else if o.CveScore >= 4 && o.CveScore <= 7 {
		o.Sensibility = "MEDIUM"
	} else if o.CveScore < 4 {
		o.Sensibility = "LOW"
	}
	o.CveList = utils.RemoveDuplicates(o.CveList)
}

func (o *QnapTurboNas) PrintInfo() string {
	return model.Category.NetworkStorage() + " | Qnap Turbo Station"
}

func (o *QnapTurboNas) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    o.Category,
		DeviceName:  o.DeviceName,
		Version:     o.Version,
		CveList:     o.CveList,
		Sensibility: o.Sensibility,
		CveScore:    o.CveScore,
	}
}
