package secrets

import "testing"

func TestKind(t *testing.T) {
	for in, want := range map[string]string{
		"":                       "",
		"hunter2":                "plain",
		"env:X":                  "env",
		"keychain:hiccup/site/a": "keychain",
	} {
		if got := Kind(in); got != want {
			t.Errorf("Kind(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResolve(t *testing.T) {
	t.Setenv("HICCUP_TEST_PW", "s3cret")
	if v, err := Resolve("env:HICCUP_TEST_PW"); err != nil || v != "s3cret" {
		t.Errorf("env: %q %v", v, err)
	}
	if _, err := Resolve("env:HICCUP_DEFINITELY_UNSET_VAR"); err == nil {
		t.Error("unset env var should fail")
	}
	if v, _ := Resolve("plain-pw"); v != "plain-pw" {
		t.Errorf("plain: %q", v)
	}
}

func TestSplitKeychain(t *testing.T) {
	svc, acct, err := splitKeychain("keychain:hiccup/acme/user2")
	if err != nil || svc != "hiccup" || acct != "acme/user2" {
		t.Errorf("got %q %q %v", svc, acct, err)
	}
	for _, bad := range []string{"keychain:", "keychain:svc", "keychain:/acct", "keychain:svc/"} {
		if _, _, err := splitKeychain(bad); err == nil {
			t.Errorf("%q should fail", bad)
		}
	}
}
