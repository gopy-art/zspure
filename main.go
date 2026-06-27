package main

import (
	"zspure/config"
	"zspure/config/cmd"
	"zspure/logic"
	"zspure/modules"
	"zspure/online"
	"zspure/tasks"
	"zspure/tasks/zgrab2"
	"zspure/utils"
)

func init() {
	cmd.InitLoggerStdout()
	cmd.SetupFlags()
	if err := utils.ValidateFlags(); err != nil {
		cmd.ErrorLogger.Fatalln(err)
	}
}

func main() {
	switch config.LOGIC {
	case "execute":
		conf, erc := config.ParseConfig(config.CONFIG_PATH)
		if erc != nil {
			cmd.ErrorLogger.Fatalf("error in config, error = %v \n", erc)
		}

		logic.AppExecute(conf)
	case "print":
		if config.PROTOCOL_INFO {
			modules.PrintModuleProtocols()
		} else if config.DEVICE_INFO {
			modules.PrintModuleDevices()
		}
	case "file":
		var strcontent string
		var bytecontent []byte
		var err error
		if config.STDIN_INPUT {
			if strcontent, bytecontent, err = utils.ReadStdin(); err != nil {
				cmd.ErrorLogger.Fatalf("error in reading stdin, error = %v \n", err)
			}
		} else {
			if strcontent, bytecontent, err = utils.ReadFile(config.INPUTFILE); err != nil {
				cmd.ErrorLogger.Fatalf("error in reading file, error = %v \n", err)
			}
		}

		if config.ZGRAB_INPUT {
			structure, err := zgrab2.ParseZgrabInput(bytecontent)
			if err != nil {
				cmd.ErrorLogger.Fatalf("error in parse the zgrab input, error = %v\n", err)
			}
			for _, record := range structure.Data {
				zgrab2.DetectZgrabResult(record)
			}
		} else {
			tasks.DetectDeviceBaseFile(strcontent)
		}
	case "url":
		// " SendOnlineRequest " function return the body as string and error
		if _, err := online.SendOnlineRequest(config.URL); err != nil {
			cmd.ErrorLogger.Fatalf("error in detecting device, error = %v \n", err)
		}
	default:
		cmd.ErrorLogger.Fatalf("The type of execution is invalid")
	}
}
