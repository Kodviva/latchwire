package ipc

import (
	"reflect"
	"slices"
	"testing"
)

// Equal must compare every field: a field added to TunnelStatus without
// being added to Equal makes the desktop app miss that change.
func TestTunnelStatusEqualCoversEveryField(t *testing.T) {
	base := TunnelStatus{Name: "a", State: "s", Identity: "i", Keys: []string{"k"}, LastHandshake: "h",
		Interface: "if", MTU: 1, FullTunnel: true, DNS: "d", KillSwitch: "ks", Warning: "w"}
	if !base.Equal(base) {
		t.Fatal("not equal to itself")
	}
	v := reflect.ValueOf(&base).Elem()
	for i := range v.NumField() {
		o := base
		o.Keys = slices.Clone(base.Keys)
		f := reflect.ValueOf(&o).Elem().Field(i)
		f.Set(reflect.Zero(f.Type()))
		if base.Equal(o) {
			t.Errorf("Equal ignores %s", v.Type().Field(i).Name)
		}
	}
}
