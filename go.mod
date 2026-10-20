module github.com/Kodviva/latchwire

go 1.25

replace golang.zx2c4.com/wireguard => ./third_party/wireguard-go

require (
	github.com/go-piv/piv-go/v2 v2.5.0
	golang.org/x/crypto v0.37.0
	golang.org/x/time v0.7.0
	golang.zx2c4.com/wireguard v0.0.0-00010101000000-000000000000
)

require (
	golang.org/x/net v0.39.0 // indirect
	golang.org/x/sys v0.32.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
)
