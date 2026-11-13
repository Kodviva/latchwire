package daemon

import "testing"

func TestDescribeAgents(t *testing.T) {
	views := []agentView{
		{seq: 5, uid: 501, serials: []uint32{40727512}, closed: true},
		{seq: 3, uid: 501, serials: []uint32{40727513}},
		{seq: 1, uid: 502, serials: []uint32{40727512}},
		{seq: 0, uid: 501}, // connected, never registered
	}
	got := describeAgents(501, 40727512, views)
	want := "agents of uid 501: #3 cards [40727513], #5 cards [40727512] closed; card 40727512 reported by #5"
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
	if got := describeAgents(501, 1, nil); got != "agents of uid 501: none" {
		t.Fatalf("no agents: %q", got)
	}
	got = describeAgents(501, 99, views[1:2])
	if want := "agents of uid 501: #3 cards [40727513]; no agent reports card 99"; got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}
