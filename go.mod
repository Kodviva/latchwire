module github.com/Kodviva/latchwire

go 1.27.3

replace golang.zx2c4.com/wireguard => ./third_party/wireguard-go

// piv-go v2.5.0 with Latchwire patches, see third_party/piv-go/PATCHES.md.
replace github.com/go-piv/piv-go/v2 => ./third_party/piv-go

require (
	github.com/go-piv/piv-go/v2 v2.5.0
	golang.org/x/crypto v0.58.0
	golang.org/x/net v0.62.0
	golang.org/x/sys v0.49.0
	golang.org/x/term v0.47.0
	golang.org/x/time v0.16.0
	golang.zx2c4.com/wireguard v0.0.0-00010101000000-000000000000
)

require (
	github.com/google/btree v1.1.2 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	gvisor.dev/gvisor v0.0.0-20250503011706-39ed1f5ac29c // indirect
)
