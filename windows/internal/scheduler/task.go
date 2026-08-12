package scheduler

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"

	"aionuiportal/internal/auth"
	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"golang.org/x/sys/windows"
)

const (
	taskCreateOrUpdate      = 6
	taskDontAddPrincipalACE = 16
	taskLogonPassword       = 1
	taskServiceReadExecute  = windows.ACCESS_MASK(0x001200a9)
	taskStateRunning        = 4
	taskResultStillRunning  = 0x00041301
)

var (
	oleaut32           = windows.NewLazySystemDLL("oleaut32.dll")
	procSysAllocString = oleaut32.NewProc("SysAllocStringLen")
	procSysStringLen   = oleaut32.NewProc("SysStringLen")
	procSysFreeString  = oleaut32.NewProc("SysFreeString")
)

type Controller struct{}

type Spec struct {
	WindowsSID         string
	WindowsUsername    string
	Executable         string
	ConfigPath         string
	StartupCapturePath string
	WorkingDirectory   string
	PortalServiceSID   string
}

type Info struct {
	Name           string
	State          int32
	LastTaskResult int32
	XML            string
	SecuritySDDL   string
}

// IsRunning reports the two Task Scheduler signals used while a task action
// is still active. LastTaskResult is 0x41301 until the action exits, even
// though that value is often mistaken for a task failure code.
func (i Info) IsRunning() bool {
	return i.State == taskStateRunning || i.LastTaskResult == taskResultStillRunning
}

// Check verifies that the local Task Scheduler COM service and root folder are
// reachable without creating, updating, or running a task.
func (Controller) Check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return withFolder(func(*ole.IDispatch) error { return nil })
}

func TaskName(sid string) (string, error) {
	if !validSID(sid) {
		return "", errors.New("invalid Windows SID")
	}
	return "AionUiWeb-" + sid, nil
}

func (Controller) Start(ctx context.Context, sid string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	name, err := TaskName(sid)
	if err != nil {
		return err
	}
	return withFolder(func(folder *ole.IDispatch) error {
		registered, err := dispatchResult(oleutil.CallMethod(folder, "GetTask", name))
		if err != nil {
			return fmt.Errorf("open scheduled task %s: %w", name, err)
		}
		defer registered.Release()
		running, err := oleutil.CallMethod(registered, "Run", nil)
		if err != nil {
			return fmt.Errorf("run scheduled task %s: %w", name, err)
		}
		if dispatch := running.ToIDispatch(); dispatch != nil {
			dispatch.Release()
		}
		return nil
	})
}

// Register creates or updates the fixed on-demand UserHost task. It takes
// ownership of password and overwrites it before returning on every path.
func (Controller) Register(ctx context.Context, spec Spec, password []byte) error {
	defer auth.Zero(password)
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateSpec(spec); err != nil {
		return err
	}
	if len(password) == 0 {
		return errors.New("Windows password must not be empty")
	}
	name, _ := TaskName(spec.WindowsSID)
	taskXML := buildXML(spec)
	secret, err := allocSecureBSTR(password)
	if err != nil {
		return err
	}
	defer secret.close()
	sddl := taskSDDL(spec.PortalServiceSID)
	return withFolder(func(folder *ole.IDispatch) error {
		result, err := callRegisterTask(folder, name, taskXML, spec.WindowsUsername, secret, sddl)
		if err != nil {
			return fmt.Errorf("register password-logon scheduled task %s: %w", name, err)
		}
		if registered := result.ToIDispatch(); registered != nil {
			registered.Release()
		}
		return nil
	})
}

type dispatchParams struct {
	arguments          uintptr
	namedArguments     uintptr
	argumentCount      uint32
	namedArgumentCount uint32
}

func callRegisterTask(folder *ole.IDispatch, name, taskXML, username string, password *secureBSTR, sddl string) (*ole.VARIANT, error) {
	displayID, err := folder.GetSingleIDOfName("RegisterTask")
	if err != nil {
		return nil, err
	}
	values := []string{name, taskXML, username, sddl}
	bstrs := make([]*int16, len(values))
	for index, value := range values {
		bstrs[index] = ole.SysAllocStringLen(value)
		if bstrs[index] == nil {
			for _, allocated := range bstrs[:index] {
				_ = ole.SysFreeString(allocated)
			}
			return nil, errors.New("allocate Task Scheduler argument BSTR")
		}
	}
	defer func() {
		for _, allocated := range bstrs {
			_ = ole.SysFreeString(allocated)
		}
	}()

	// IDispatch arguments are ordered right-to-left. The password must be a
	// by-value VT_BSTR: go-ole's *VARIANT handling produces VT_VARIANT|VT_BYREF,
	// which Task Scheduler rejects with E_UNEXPECTED before checking credentials.
	arguments := registerTaskArguments(password, bstrs)
	params := dispatchParams{arguments: uintptr(unsafe.Pointer(&arguments[0])), argumentCount: uint32(len(arguments))}
	result := new(ole.VARIANT)
	if err := ole.VariantInit(result); err != nil {
		return nil, err
	}
	var exception ole.EXCEPINFO
	hresult, _, _ := syscall.Syscall9(
		folder.VTable().Invoke,
		9,
		uintptr(unsafe.Pointer(folder)),
		uintptr(displayID),
		uintptr(unsafe.Pointer(ole.IID_NULL)),
		uintptr(ole.GetUserDefaultLCID()),
		uintptr(ole.DISPATCH_METHOD),
		uintptr(unsafe.Pointer(&params)),
		uintptr(unsafe.Pointer(result)),
		uintptr(unsafe.Pointer(&exception)),
		0,
	)
	runtime.KeepAlive(arguments)
	runtime.KeepAlive(bstrs)
	runtime.KeepAlive(password)
	if hresult != 0 {
		description := exception.Error()
		exceptionCode := exception.SCODE()
		exception.Clear()
		_ = result.Clear()
		message := fmt.Sprintf("%s (HRESULT=0x%08x)", ole.NewError(hresult), uint32(hresult))
		if exceptionCode != 0 || description != "<nil>: 0x0" {
			message += fmt.Sprintf("; exception=0x%08x %s", exceptionCode, description)
		}
		return nil, errors.New(message)
	}
	exception.Clear()
	return result, nil
}

func registerTaskArguments(password *secureBSTR, bstrs []*int16) []ole.VARIANT {
	return []ole.VARIANT{
		ole.NewVariant(ole.VT_BSTR, int64(uintptr(unsafe.Pointer(bstrs[3])))),
		ole.NewVariant(ole.VT_I4, int64(taskLogonPassword)),
		ole.NewVariant(ole.VT_BSTR, int64(password.pointer)),
		ole.NewVariant(ole.VT_BSTR, int64(uintptr(unsafe.Pointer(bstrs[2])))),
		ole.NewVariant(ole.VT_I4, int64(taskCreateOrUpdate|taskDontAddPrincipalACE)),
		ole.NewVariant(ole.VT_BSTR, int64(uintptr(unsafe.Pointer(bstrs[1])))),
		ole.NewVariant(ole.VT_BSTR, int64(uintptr(unsafe.Pointer(bstrs[0])))),
	}
}

func (Controller) Remove(ctx context.Context, sid string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	name, err := TaskName(sid)
	if err != nil {
		return err
	}
	return withFolder(func(folder *ole.IDispatch) error {
		result, err := oleutil.CallMethod(folder, "DeleteTask", name, int32(0))
		if result != nil {
			_ = result.Clear()
		}
		if err != nil {
			return fmt.Errorf("remove scheduled task %s: %w", name, err)
		}
		return nil
	})
}

func (Controller) Info(ctx context.Context, sid string) (Info, error) {
	if err := ctx.Err(); err != nil {
		return Info{}, err
	}
	name, err := TaskName(sid)
	if err != nil {
		return Info{}, err
	}
	var info Info
	err = withFolder(func(folder *ole.IDispatch) error {
		registered, err := dispatchResult(oleutil.CallMethod(folder, "GetTask", name))
		if err != nil {
			return err
		}
		defer registered.Release()
		state, err := propertyInt32(registered, "State")
		if err != nil {
			return err
		}
		last, err := propertyInt32(registered, "LastTaskResult")
		if err != nil {
			return err
		}
		xmlText, err := propertyString(registered, "Xml")
		if err != nil {
			return err
		}
		security, err := oleutil.CallMethod(registered, "GetSecurityDescriptor", int32(7))
		if err != nil {
			return err
		}
		securityText := security.ToString()
		_ = security.Clear()
		info = Info{Name: name, State: state, LastTaskResult: last, XML: xmlText, SecuritySDDL: securityText}
		return nil
	})
	return info, err
}

func VerifySpec(info Info, spec Spec) error {
	if err := validateSpec(spec); err != nil {
		return err
	}
	var document taskDocument
	if err := xml.Unmarshal([]byte(decodedTaskXML(info.XML)), &document); err != nil {
		return fmt.Errorf("parse registered task XML: %w", err)
	}
	wantArgs := `--config "` + spec.ConfigPath + `" --startup-capture "` + spec.StartupCapturePath + `"`
	legacyArgs := `--config "` + spec.ConfigPath + `"`
	principalMatches := strings.EqualFold(document.Principals.Principal.UserID, spec.WindowsUsername) || strings.EqualFold(document.Principals.Principal.UserID, spec.WindowsSID)
	runLevel := document.Principals.Principal.RunLevel
	if !principalMatches || document.Principals.Principal.LogonType != "Password" ||
		(runLevel != "" && runLevel != "LeastPrivilege") {
		return errors.New("task principal is not the configured least-privilege password-logon account")
	}
	if document.Settings.MultipleInstancesPolicy != "IgnoreNew" || !trueWhenOmitted(document.Settings.AllowStartOnDemand) || !trueWhenOmitted(document.Settings.Enabled) ||
		document.Settings.ExecutionTimeLimit != "PT0S" {
		return errors.New("task settings do not enforce the required on-demand singleton behavior")
	}
	if !samePath(document.Actions.Exec.Command, spec.Executable) ||
		(document.Actions.Exec.Arguments != wantArgs && document.Actions.Exec.Arguments != legacyArgs) ||
		!samePath(document.Actions.Exec.WorkingDirectory, spec.WorkingDirectory) {
		return errors.New("task action does not match the fixed UserHost command")
	}
	if err := verifyTaskSecurity(info.SecuritySDDL, taskSDDL(spec.PortalServiceSID)); err != nil {
		return err
	}
	return nil
}

func trueWhenOmitted(value *bool) bool {
	return value == nil || *value
}

func decodedTaskXML(value string) string {
	value = strings.TrimPrefix(value, "\ufeff")
	value = strings.TrimLeft(value, " \t\r\n")
	if strings.HasPrefix(value, "<?xml") {
		if end := strings.Index(value, "?>"); end >= 0 {
			value = value[end+2:]
		}
	}
	return value
}

func verifyTaskSecurity(actual, expected string) error {
	if strings.TrimSpace(actual) == "" {
		return errors.New("task security descriptor is unavailable")
	}
	actualOwner, actualACL, err := taskSecurityParts(actual)
	if err != nil {
		return fmt.Errorf("parse task security descriptor: %w", err)
	}
	expectedOwner, expectedACL, err := taskSecurityParts(expected)
	if err != nil {
		return fmt.Errorf("build expected task security descriptor: %w", err)
	}
	if !strings.EqualFold(actualOwner, expectedOwner) || len(actualACL) != len(expectedACL) {
		return errors.New("task security descriptor has an unexpected owner or principal set")
	}
	for sid, expectedMask := range expectedACL {
		actualMask, ok := actualACL[sid]
		if !ok || actualMask != expectedMask {
			return fmt.Errorf("task security descriptor rights for %s are 0x%08x, want 0x%08x", sid, uint32(actualMask), uint32(expectedMask))
		}
	}
	return nil
}

func taskSecurityParts(sddl string) (string, map[string]windows.ACCESS_MASK, error) {
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return "", nil, err
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return "", nil, err
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return "", nil, errors.New("task DACL inheritance is not protected")
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !owner.IsValid() {
		return "", nil, errors.New("task owner SID is invalid")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return "", nil, errors.New("task DACL is missing")
	}
	header := (*taskACLHeader)(unsafe.Pointer(dacl))
	principals := make(map[string]windows.ACCESS_MASK, header.AceCount)
	for index := uint32(0); index < uint32(header.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			return "", nil, err
		}
		if ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			return "", nil, fmt.Errorf("task DACL contains an unsupported ACE at index %d", index)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid == nil || !sid.IsValid() {
			return "", nil, fmt.Errorf("task DACL contains an invalid SID at index %d", index)
		}
		principals[strings.ToUpper(sid.String())] |= ace.Mask
	}
	return strings.ToUpper(owner.String()), principals, nil
}

type taskACLHeader struct {
	Revision byte
	Sbz1     byte
	Size     uint16
	AceCount uint16
	Sbz2     uint16
}

func validateSpec(spec Spec) error {
	if _, err := TaskName(spec.WindowsSID); err != nil {
		return err
	}
	if strings.TrimSpace(spec.WindowsUsername) == "" || !validSID(spec.PortalServiceSID) {
		return errors.New("Windows account and Portal service SID are required")
	}
	for name, value := range map[string]string{"executable": spec.Executable, "config": spec.ConfigPath, "startup capture": spec.StartupCapturePath, "working directory": spec.WorkingDirectory} {
		if !filepath.IsAbs(value) {
			return fmt.Errorf("task %s must be an absolute path", name)
		}
		if strings.ContainsAny(value, "\x00\r\n") {
			return fmt.Errorf("task %s contains an invalid character", name)
		}
	}
	return nil
}

func validSID(value string) bool {
	if len(value) < 5 || len(value) > 184 || !strings.HasPrefix(value, "S-1-") || strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	sid, err := windows.StringToSid(value)
	return err == nil && sid != nil && sid.IsValid() && strings.EqualFold(sid.String(), value)
}

func buildXML(spec Spec) string {
	escape := func(value string) string { return html.EscapeString(value) }
	arguments := `--config &quot;` + escape(spec.ConfigPath) + `&quot; --startup-capture &quot;` + escape(spec.StartupCapturePath) + `&quot;`
	return `<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">` +
		`<RegistrationInfo><Description>AionUi isolated per-user Web host</Description></RegistrationInfo>` +
		`<Principals><Principal id="UserHost"><UserId>` + escape(spec.WindowsUsername) + `</UserId><LogonType>Password</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>` +
		`<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>` +
		`<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable>` +
		`<RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>` +
		`<AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>true</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle>` +
		`<WakeToRun>false</WakeToRun><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Priority>7</Priority></Settings>` +
		`<Actions Context="UserHost"><Exec><Command>` + escape(spec.Executable) + `</Command><Arguments>` + arguments + `</Arguments><WorkingDirectory>` +
		escape(spec.WorkingDirectory) + `</WorkingDirectory></Exec></Actions></Task>`
}

func taskSDDL(portalSID string) string {
	return fmt.Sprintf("O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x%08x;;;%s)", uint32(taskServiceReadExecute), portalSID)
}

func withFolder(operation func(*ole.IDispatch) error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED); err != nil {
		return fmt.Errorf("initialize Task Scheduler COM: %w", err)
	}
	defer ole.CoUninitialize()
	unknown, err := oleutil.CreateObject("Schedule.Service")
	if err != nil {
		return fmt.Errorf("create Task Scheduler service object: %w", err)
	}
	defer unknown.Release()
	service, err := unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return fmt.Errorf("open Task Scheduler automation interface: %w", err)
	}
	defer service.Release()
	connected, err := oleutil.CallMethod(service, "Connect")
	if connected != nil {
		_ = connected.Clear()
	}
	if err != nil {
		return fmt.Errorf("connect to local Task Scheduler: %w", err)
	}
	folder, err := dispatchResult(oleutil.CallMethod(service, "GetFolder", `\`))
	if err != nil {
		return fmt.Errorf("open Task Scheduler root folder: %w", err)
	}
	defer folder.Release()
	return operation(folder)
}

func dispatchResult(result *ole.VARIANT, err error) (*ole.IDispatch, error) {
	if err != nil {
		return nil, err
	}
	if result == nil || result.ToIDispatch() == nil {
		return nil, errors.New("COM method returned no dispatch object")
	}
	return result.ToIDispatch(), nil
}

func propertyInt32(dispatch *ole.IDispatch, name string) (int32, error) {
	result, err := oleutil.GetProperty(dispatch, name)
	if err != nil {
		return 0, err
	}
	defer result.Clear()
	value, ok := result.Value().(int32)
	if !ok {
		return 0, fmt.Errorf("Task Scheduler property %s has an unexpected type", name)
	}
	return value, nil
}

func propertyString(dispatch *ole.IDispatch, name string) (string, error) {
	result, err := oleutil.GetProperty(dispatch, name)
	if err != nil {
		return "", err
	}
	value := result.ToString()
	_ = result.Clear()
	return value, nil
}

type secureBSTR struct {
	pointer uintptr
}

func allocSecureBSTR(password []byte) (*secureBSTR, error) {
	units, err := passwordUTF16(password)
	if err != nil {
		return nil, err
	}
	defer zeroUTF16(units)
	var pointer unsafe.Pointer
	if len(units) > 0 {
		pointer = unsafe.Pointer(&units[0])
	}
	bstr, _, callErr := procSysAllocString.Call(uintptr(pointer), uintptr(len(units)))
	runtime.KeepAlive(units)
	if bstr == 0 {
		return nil, fmt.Errorf("allocate Task Scheduler password BSTR: %v", callErr)
	}
	return &secureBSTR{pointer: bstr}, nil
}

func (s *secureBSTR) close() {
	if s == nil || s.pointer == 0 {
		return
	}
	length, _, _ := procSysStringLen.Call(s.pointer)
	if length > 0 {
		memory := unsafe.Slice((*uint16)(unsafe.Pointer(s.pointer)), int(length))
		zeroUTF16(memory)
		runtime.KeepAlive(memory)
	}
	procSysFreeString.Call(s.pointer)
	s.pointer = 0
}

func passwordUTF16(password []byte) ([]uint16, error) {
	if !utf8.Valid(password) {
		return nil, errors.New("Windows password is not valid UTF-8")
	}
	result := make([]uint16, 0, len(password))
	for offset := 0; offset < len(password); {
		r, size := utf8.DecodeRune(password[offset:])
		if r == 0 {
			zeroUTF16(result)
			return nil, errors.New("Windows password contains NUL")
		}
		if r <= 0xffff {
			result = append(result, uint16(r))
		} else {
			first, second := utf16.EncodeRune(r)
			result = append(result, uint16(first), uint16(second))
		}
		offset += size
	}
	return result, nil
}

func zeroUTF16(value []uint16) {
	for i := range value {
		value[i] = 0
	}
}

func samePath(a, b string) bool {
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}

type taskDocument struct {
	Principals struct {
		Principal struct {
			UserID    string `xml:"UserId"`
			LogonType string `xml:"LogonType"`
			RunLevel  string `xml:"RunLevel"`
		} `xml:"Principal"`
	} `xml:"Principals"`
	Settings struct {
		MultipleInstancesPolicy string `xml:"MultipleInstancesPolicy"`
		AllowStartOnDemand      *bool  `xml:"AllowStartOnDemand"`
		Enabled                 *bool  `xml:"Enabled"`
		ExecutionTimeLimit      string `xml:"ExecutionTimeLimit"`
	} `xml:"Settings"`
	Actions struct {
		Exec struct {
			Command          string `xml:"Command"`
			Arguments        string `xml:"Arguments"`
			WorkingDirectory string `xml:"WorkingDirectory"`
		} `xml:"Exec"`
	} `xml:"Actions"`
}
