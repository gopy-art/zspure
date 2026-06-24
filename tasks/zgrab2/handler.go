package zgrab2

import (
	"encoding/json"
	"fmt"
	"slices"
	"sync"
	"zspure/config"
	"zspure/config/cmd"
	"zspure/modules"
	"zspure/modules/model"
)

func ParseZgrabInput(content []byte) (*ZgrabModel, error) {
	model := ZgrabModel{}
	err := model.Parse(content)
	return &model, err
}

func DetectZgrabResult(data zgrabDataModel) error {
	var wg sync.WaitGroup
	m := model.GatherModuleSructure{
		Protocol: data.Protocol,
		Banner:   data.Result,
	}

	handlers, err := modules.NewModule(m.Protocol)
	if err != nil {
		return err
	} else {
		for devices := range slices.Chunk(handlers, 10) {
			for _, device := range devices {
				wg.Go(func() {
					if res := device.Filters(m.Banner); res {
						device.SetCategory()
						device.SetDeviceName()
						device.DeviceScan(m.Banner)
						if config.FIND_CVE {
							device.CveScan(nil)
						}

						if config.JSON_OUTPUT {
							if buf, err := json.Marshal(device.Result()); err != nil {
								cmd.ErrorLogger.Printf("error in marshal the result, error = %v\n", err)
							} else {
								fmt.Printf("%s\n", buf)
							}
						} else {
							fmt.Printf("Detected Device = %v | Category = %v | Version = %v\n", device.Result().DeviceName, device.Result().Category, device.Result().Version)
						}
					}
				})
			}
			wg.Wait()
		}
	}
	return nil
}
