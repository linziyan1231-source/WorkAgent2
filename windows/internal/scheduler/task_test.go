package scheduler

import (
	"context"
	"encoding/xml"
	"strings"
	"testing"
	"time"

	"github.com/go-ole/go-ole"
)

func TestInfoIsRunningRecognizesTaskSchedulerSignals(t *testing.T) {
	if !(Info{State: taskStateRunning}).IsRunning() {
		t.Fatal("running task state was not recognized")
	}
	if !(Info{LastTaskResult: taskResultStillRunning}).IsRunning() {
		t.Fatal("0x41301 still-running result was not recognized")
	}
	if (Info{State: 3, LastTaskResult: 1}).IsRunning() {
		t.Fatal("finished task was reported as running")
	}
}

func TestTaskSchedulerCOMIsReachableReadOnly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := (Controller{}).Check(ctx); err != nil {
		t.Fatalf("Task Scheduler COM root is unavailable: %v", err)
	}
}

func TestTaskXMLIsFixedPasswordLogonSingletonWithoutPassword(t *testing.T) {
	spec := testSpec()
	documentXML := buildXML(spec)
	if strings.Contains(documentXML, "Never-Store-This-Windows-Password") {
		t.Fatal("task XML contains a Windows password")
	}
	var document taskDocument
	if err := xml.Unmarshal([]byte(documentXML), &document); err != nil {
		t.Fatal(err)
	}
	info := Info{XML: documentXML, SecuritySDDL: taskSDDL(spec.PortalServiceSID)}
	if err := VerifySpec(info, spec); err != nil {
		t.Fatal(err)
	}
	if document.Settings.MultipleInstancesPolicy != "IgnoreNew" || document.Principals.Principal.LogonType != "Password" || document.Principals.Principal.RunLevel != "LeastPrivilege" {
		t.Fatalf("unsafe task definition: %#v", document)
	}
	utf16Declared := info
	utf16Declared.XML = "\ufeff  <?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n" + documentXML
	if err := VerifySpec(utf16Declared, spec); err != nil {
		t.Fatalf("Task Scheduler UTF-16-declared BSTR XML was rejected: %v", err)
	}
	canonicalized := info
	canonicalized.XML = strings.Replace(documentXML, "<RunLevel>LeastPrivilege</RunLevel>", "", 1)
	if err := VerifySpec(canonicalized, spec); err != nil {
		t.Fatalf("Task Scheduler omitted default RunLevel was rejected: %v", err)
	}
	canonicalized.XML = strings.Replace(canonicalized.XML, "<AllowStartOnDemand>true</AllowStartOnDemand>", "", 1)
	canonicalized.XML = strings.Replace(canonicalized.XML, "<Enabled>true</Enabled>", "", 1)
	if err := VerifySpec(canonicalized, spec); err != nil {
		t.Fatalf("Task Scheduler omitted true-by-default settings were rejected: %v", err)
	}
	disabledXML := info
	disabledXML.XML = strings.Replace(documentXML, "<Enabled>true</Enabled>", "<Enabled>false</Enabled>", 1)
	if err := VerifySpec(disabledXML, spec); err == nil {
		t.Fatal("disabled task definition was accepted")
	}
	elevatedXML := info
	elevatedXML.XML = strings.Replace(documentXML, "<RunLevel>LeastPrivilege</RunLevel>", "<RunLevel>HighestAvailable</RunLevel>", 1)
	if err := VerifySpec(elevatedXML, spec); err == nil {
		t.Fatal("highest-available task principal was accepted")
	}
}

func TestTaskSecurityDescriptorRejectsExtraPrincipalOrElevatedServiceRights(t *testing.T) {
	spec := testSpec()
	base := Info{XML: buildXML(spec), SecuritySDDL: taskSDDL(spec.PortalServiceSID)}
	if err := VerifySpec(base, spec); err != nil {
		t.Fatal(err)
	}
	owner, principals, err := taskSecurityParts(base.SecuritySDDL)
	if err != nil {
		t.Fatal(err)
	}
	if owner != "S-1-5-32-544" {
		t.Fatalf("task owner=%s, want built-in Administrators", owner)
	}
	if principals[strings.ToUpper(spec.PortalServiceSID)] != taskServiceReadExecute {
		t.Fatalf("Portal service task mask=%#x, want %#x", principals[strings.ToUpper(spec.PortalServiceSID)], taskServiceReadExecute)
	}
	extra := base
	extra.SecuritySDDL += "(A;;GR;;;BU)"
	if err := VerifySpec(extra, spec); err == nil {
		t.Fatal("task ACL with an extra Users principal was accepted")
	}
	elevated := base
	elevated.SecuritySDDL = strings.Replace(base.SecuritySDDL, "0x001200a9", "FA", 1)
	if err := VerifySpec(elevated, spec); err == nil {
		t.Fatal("task ACL granting full control to the Portal service was accepted")
	}
}

func TestPasswordUTF16PreservesUnicodeAndRejectsNUL(t *testing.T) {
	units, err := passwordUTF16([]byte("Pass-密码-🙂"))
	if err != nil {
		t.Fatal(err)
	}
	if len(units) != 10 {
		t.Fatalf("UTF-16 unit count=%d", len(units))
	}
	zeroUTF16(units)
	for _, unit := range units {
		if unit != 0 {
			t.Fatal("password UTF-16 buffer was not cleared")
		}
	}
	if _, err := passwordUTF16([]byte{'a', 0, 'b'}); err == nil {
		t.Fatal("NUL password was accepted")
	}
}

func TestRegisterTaskPasswordArgumentIsByValueBSTR(t *testing.T) {
	secret, err := allocSecureBSTR([]byte("Never-Store-This-Windows-Password"))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.close()
	arguments := registerTaskArguments(secret, make([]*int16, 4))
	password := arguments[2]
	if password.VT != ole.VT_BSTR || password.VT&ole.VT_BYREF != 0 || uintptr(password.Val) != secret.pointer {
		t.Fatalf("RegisterTask password argument is not a by-value BSTR: VT=%#x", password.VT)
	}
	flags := arguments[4]
	if flags.VT != ole.VT_I4 || flags.Val != taskCreateOrUpdate|taskDontAddPrincipalACE {
		t.Fatalf("RegisterTask flags=%#x/%d, want TASK_CREATE_OR_UPDATE|TASK_DONT_ADD_PRINCIPAL_ACE", flags.VT, flags.Val)
	}
}

func TestTaskNameRejectsInputOutsideSIDGrammar(t *testing.T) {
	for _, value := range []string{"test1", "S-1-5-21-1/other", "S-1-5-x", ""} {
		if _, err := TaskName(value); err == nil {
			t.Fatalf("accepted invalid SID %q", value)
		}
	}
}

func testSpec() Spec {
	return Spec{
		WindowsSID:       "S-1-5-21-100-200-300-1017",
		WindowsUsername:  `SERVER\test1`,
		Executable:       `C:\Program Files\AionUiPortal\AionUiUserHost.exe`,
		ConfigPath:       `C:\ProgramData\AionUiPortal\users\S-1-5-21-100-200-300-1017\userhost.json`,
		WorkingDirectory: `C:\Program Files\AionUiPortal`,
		PortalServiceSID: "S-1-5-80-123-456-789",
	}
}
