package winutil

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	afInet                   = 2
	tcpTableOwnerPIDListener = 3
	tcpStateListen           = 2
)

type TCPListener struct {
	PID     uint32
	Address net.IP
	Port    int
}

type mibTCPRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPID  uint32
}

var (
	iphlpapi                = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTCPTable = iphlpapi.NewProc("GetExtendedTcpTable")
)

func TCPListeners() ([]TCPListener, error) {
	var size uint32
	r1, _, _ := procGetExtendedTCPTable.Call(0, uintptr(unsafe.Pointer(&size)), 1, afInet, tcpTableOwnerPIDListener, 0)
	if r1 != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) || size < 4 {
		return nil, fmt.Errorf("size TCP table: Windows error %d", r1)
	}
	buf := make([]byte, size)
	r1, _, _ = procGetExtendedTCPTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 1, afInet, tcpTableOwnerPIDListener, 0)
	if r1 != 0 {
		return nil, fmt.Errorf("read TCP table: Windows error %d", r1)
	}
	count := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := unsafe.Sizeof(mibTCPRowOwnerPID{})
	if uintptr(4)+uintptr(count)*rowSize > uintptr(len(buf)) {
		return nil, errors.New("Windows returned a truncated TCP table")
	}
	listeners := make([]TCPListener, 0, count)
	base := uintptr(unsafe.Pointer(&buf[0])) + 4
	for i := uint32(0); i < count; i++ {
		row := (*mibTCPRowOwnerPID)(unsafe.Pointer(base + uintptr(i)*rowSize))
		if row.State != tcpStateListen {
			continue
		}
		addrBytes := (*[4]byte)(unsafe.Pointer(&row.LocalAddr))
		port := int((row.LocalPort&0xff)<<8 | (row.LocalPort>>8)&0xff)
		listeners = append(listeners, TCPListener{PID: row.OwningPID, Address: net.IPv4(addrBytes[0], addrBytes[1], addrBytes[2], addrBytes[3]), Port: port})
	}
	sort.Slice(listeners, func(i, j int) bool {
		if listeners[i].PID != listeners[j].PID {
			return listeners[i].PID < listeners[j].PID
		}
		return listeners[i].Port < listeners[j].Port
	})
	return listeners, nil
}

func VerifyLoopbackListener(pid uint32, port int) error {
	listeners, err := TCPListeners()
	if err != nil {
		return err
	}
	found := false
	for _, listener := range listeners {
		if listener.Port != port {
			continue
		}
		if listener.PID != pid {
			return fmt.Errorf("port %d belongs to PID %d, expected PID %d", port, listener.PID, pid)
		}
		found = true
		if !listener.Address.Equal(net.IPv4(127, 0, 0, 1)) {
			return fmt.Errorf("PID %d port %d is not bound exclusively to 127.0.0.1 (address %s)", pid, port, listener.Address)
		}
	}
	if !found {
		return fmt.Errorf("PID %d has no TCP listener on port %d", pid, port)
	}
	return nil
}
