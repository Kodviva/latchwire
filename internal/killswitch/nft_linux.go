package killswitch

import (
	"context"
	"time"

	"github.com/Kodviva/latchwire/internal/netcfg"
)

// probeTimeout bounds New's check for nft.
const probeTimeout = 10 * time.Second

func newPlatform(r netcfg.Runner, j *netcfg.Journal) (Firewall, error) {
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	return newNft(ctx, r, j)
}
