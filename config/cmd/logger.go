package cmd

import (
	"io"
	"log"
	"os"
)

var (
	InfoLogger    *log.Logger
	ErrorLogger   *log.Logger
	SuccessLogger *log.Logger
	WarningLogger *log.Logger
)

/*
This function is for initialize the log file and put the logs in file.
*/
func InitLoggerFile(logPath string) {
	file, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
	}
	wrt := io.MultiWriter(file)
	InfoLogger = log.New(file, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	InfoLogger.SetOutput(wrt)
	ErrorLogger = log.New(file, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
	ErrorLogger.SetOutput(wrt)
	SuccessLogger = log.New(wrt, "Success: ", log.Ldate|log.Ltime|log.Lshortfile)
	SuccessLogger.SetOutput(wrt)
	WarningLogger = log.New(wrt, "Warning: ", log.Ldate|log.Ltime|log.Lshortfile)
	WarningLogger.SetOutput(wrt)
}

/*
This function is for initialize the log stdout and write the logs in stdout.
*/
func InitLoggerStdout() {
	wrt := io.MultiWriter(os.Stdout)
	InfoLogger = log.New(wrt, "\033[1;34mINFO:\033[0m ", log.Ldate|log.Ltime|log.Lshortfile)
	SuccessLogger = log.New(wrt, "\033[1;32mSuccess:\033[0m ", log.Ldate|log.Ltime|log.Lshortfile)
	ErrorLogger = log.New(wrt, "\x1b[38;2;255;0;0mERROR:\x1b[0m ", log.Ldate|log.Ltime|log.Lshortfile)
	WarningLogger = log.New(wrt, "\033[1;33mWarning: \033[0m", log.Ldate|log.Ltime|log.Lshortfile)
	InfoLogger.SetOutput(wrt)
	SuccessLogger.SetOutput(wrt)
	ErrorLogger.SetOutput(wrt)
	WarningLogger.SetOutput(wrt)
}