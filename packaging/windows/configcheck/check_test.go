package configcheck

import "testing"

func TestValidateWindowsPathIsCrossPlatform(t *testing.T) {
	valid := []string{
		`C:\ProgramData\netp2p\data`,
		`C:/ProgramData/netp2p`,
		`\\server\netp2p\data`,
	}
	for _, value := range valid {
		if err := validateWindowsPath("dataDir", value); err != nil {
			t.Fatalf("validateWindowsPath(%q) = %v, want nil", value, err)
		}
	}

	invalid := []string{
		`C:`,
		`C:relative`,
		`/var/lib/netp2p`,
		`programdata\netp2p`,
	}
	for _, value := range invalid {
		if err := validateWindowsPath("dataDir", value); err == nil {
			t.Fatalf("validateWindowsPath(%q) = nil, want error", value)
		}
	}
}
