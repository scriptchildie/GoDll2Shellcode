package main

import (
	"os"
	"strconv"

	"golang.org/x/sys/windows"
)

func AttachWindbg() error {
	// Get the current process ID
	pid := os.Getpid()
	var startupInfo windows.StartupInfo
	var outProcInfo windows.ProcessInformation

	return windows.CreateProcess(
		nil,
		windows.StringToUTF16Ptr("WinDbgX /g /p "+strconv.Itoa(pid)),
		nil,
		nil,
		false,
		0,
		nil,
		nil,
		&startupInfo,
		&outProcInfo,
	)

}
