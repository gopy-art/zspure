package logic

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"zspure/config"
	"zspure/config/cmd"
	"zspure/handler"
	"zspure/modules"
	"zspure/modules/model"
)

var (
	TASKQUEUE chan map[string]interface{} = make(chan map[string]interface{})
)

func AppExecute(conf *config.Config) {
	els := handler.Elastic{
		URL:      conf.ElasticUrl,
		APIKey:   conf.ElasticApiKey,
		CveIndex: conf.IndexOfCVE,
	}
	els.ElasticConnection()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		var buf bytes.Buffer
		for obj := range TASKQUEUE {
			if val, ok := obj["status"]; ok && (val.(string) == "done") {
				wg.Done()
				break
			}
			m := model.NewModuleStructure(obj)

			if config.CLEAR != "" {
				els.DeleteFields(m.Index, m.ID, []string{"device_name", "dvs_category", "version"})
				continue
			}

			handlers, err := modules.NewModule(m.Protocol)
			if err != nil {
				cmd.ErrorLogger.Printf("we have an error, error = %v\n", err)
			} else {
				for _, method := range handlers {
					if res := method.Filters(m.Banner); res {
						method.SetCategory()
						method.SetDeviceName()
						method.DeviceScan(m.Banner)
						if config.FIND_CVE {
							method.CveScan(&els)
						}

						// fmt.Printf("%v    %v	%+v\n", m.ID, m.IP, method.Result())

						// Convert 'method.Result' argument to JSON
						if err := json.NewEncoder(&buf).Encode(map[string]interface{}{"doc": method.Result()}); err != nil {
							cmd.ErrorLogger.Printf("Error in marshal the Result, IP: %v , ID: %v , Error: %v\n", m.IP, m.ID, err)
						}

						if ok := els.UpdateSingleData(m.Index, m.ID, buf); ok != nil {
							cmd.ErrorLogger.Printf("Error in update the object, IP: %v , ID: %v , Error: %v\n", m.IP, m.ID, ok)
						} else {
							cmd.SuccessLogger.Printf(" ::::: object with ID {%v} and IP {%v} clarified. Device = %v\n", m.ID, m.IP, method.Result().DeviceName)
						}
						buf.Reset()
					}
				}
			}
		}
	}()

	// calculate the Dork and query
	mustExistQuery := []string{}
	term := map[string]interface{}{
		"status": "success",
	}

	if config.TAG != "" {
		term["tag.keyword"] = config.TAG
	}

	if config.CLEAR != "" {
		term[fmt.Sprintf("%v.keyword", config.KEY)] = config.CLEAR
	} else {
		mustExistQuery = append(mustExistQuery, "dvs_category")
	}

	for _, v := range conf.ElasticIndices {
		if strings.Contains(strings.ToLower(v), "http") {
			if len(conf.Devices) == 0 {
				els.GatherAllDataInQueue(TASKQUEUE, v, map[string]interface{}{
					"term": term,
					"must_not_exists": mustExistQuery,
				})
			} else {
				handlers, err := modules.NewModule("http")
				if err == nil {
					for _, dv := range conf.Devices {						
						for _, dvs := range handlers {
							if dvs.PrintInfo() == dv {
								els.GatherAllDataInQueue(TASKQUEUE, v, map[string]interface{}{
									"term": term,
									"should": dvs.Patterns(),
									"must_not_exists": mustExistQuery,
								})
							}
						}
					}
				}
			}
		} else {
			els.GatherAllDataInQueue(TASKQUEUE, v, map[string]interface{}{
				"term": term,
				"must_not_exists": mustExistQuery,
			})
		}
	}
	TASKQUEUE <- map[string]interface{}{"status": "done"}
	wg.Wait()
}
