package ipc

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestAssistTypesRoundTrip(t *testing.T) {
	ts := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	cases := []any{
		AssistCall{Client: "claude", Tool: "list_cards", Args: json.RawMessage(`{"a":1}`)},
		AssistGrant{Minutes: 60, Groups: []string{GroupKeys, GroupTunnels, GroupConnect}},
		AssistActivity{Entries: []ActivityEntry{{Time: ts, Client: "c", Tool: "t", Summary: "s", Result: "ok"}}},
		ApproveRequest{Client: "c", Tool: "create_key", Summary: "s", Fresh: true},
		ApproveResult{Allow: true},
		CardListResult{Cards: []CardEntry{{Serial: 7, Firmware: "5.7.1", Supported: true, Fresh: true, FreeSlots: Slots{1, 2}, Keys: []string{"yk:7:9a"}}}},
		KeygenRequest{Serial: 7, Slot: 2},
		KeygenResult{Ref: "r", Public: "AAAA"},
		AssistNotice{Step: "pin"},
		AssistResult{Data: json.RawMessage(`{"x":true}`), Summary: "done"},
	}
	for _, c := range cases {
		b, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		got := reflect.New(reflect.TypeOf(c))
		if err := json.Unmarshal(b, got.Interface()); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got.Elem().Interface(), c) {
			t.Errorf("%T: got %+v, want %+v", c, got.Elem().Interface(), c)
		}
	}

	b, _ := json.Marshal(AgentRegister{Serials: []uint32{1}})
	if strings.Contains(string(b), "caps") {
		t.Errorf("empty caps serialized: %s", b)
	}
	b, _ = json.Marshal(AgentRegister{Serials: []uint32{1}, Caps: []string{CapAssist}})
	if !strings.Contains(string(b), `"caps":["assist"]`) {
		t.Errorf("caps missing: %s", b)
	}
}

func TestSlotsWireForm(t *testing.T) {
	e := CardEntry{Serial: 1, FreeSlots: Slots{0x82, 0x83, 0x95}}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"freeSlots":[130,131,149]`) {
		t.Fatalf("wire form %s", b)
	}
	var back CardEntry
	if err := json.Unmarshal(b, &back); err != nil || !reflect.DeepEqual(back, e) {
		t.Fatalf("round trip %+v, %v", back, err)
	}
	if b, _ := json.Marshal(CardEntry{}); strings.Contains(string(b), "freeSlots") {
		t.Fatalf("empty slots written: %s", b)
	}
}

func TestSlotsDecodeOldBase64(t *testing.T) {
	var e CardEntry
	if err := json.Unmarshal([]byte(`{"serial":1,"freeSlots":"goOV"}`), &e); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(e.FreeSlots, Slots{0x82, 0x83, 0x95}) {
		t.Fatalf("got %v", e.FreeSlots)
	}
	if err := json.Unmarshal([]byte(`{"freeSlots":[300]}`), &e); err == nil {
		t.Fatal("slot 300 accepted")
	}
}
