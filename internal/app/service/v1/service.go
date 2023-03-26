package service

import (
	"context"
	"log"
	"time"

	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"github.com/stone-wlg/envoy-xds-server/internal/pkg/utils/v1"
)

var (
	snapshotCache cache.SnapshotCache
)

func init() {
	snapshotCache = cache.NewSnapshotCache(false, cache.IDHash{}, nil)
}

func RunServer(config *utils.XDSServerConfig) {
	// Init database
	err := utils.InitDatabase(config)
	if err != nil {
		panic(err.Error())
	}

	go refreshSnapShotCache(config)

	// Run the xDS server
	ctx := context.Background()
	srv := server.NewServer(ctx, snapshotCache, nil)
	utils.RunServer(ctx, srv, uint(config.Peer.Port))
}

func refreshSnapShotCache(config *utils.XDSServerConfig) {
	for {
		peers := utils.GetPeers(config.Mysql.PeerSQL)
		services := utils.GetServices(config.Mysql.ServiceSQL)

		snapshot := utils.GenerateSnapshots(config, peers, services)
		if err := snapshot.Consistent(); err != nil {
			log.Printf("snapshot inconsistency: %+v\n%+v", snapshot, err)
			continue
		}

		if err := snapshotCache.SetSnapshot(context.Background(), config.Peer.Id, snapshot); err != nil {
			log.Printf("snapshot error %q for %+v", snapshot, err)
			continue
		}

		time.Sleep(time.Duration(config.Peer.RefreshInterval) * time.Second)
	}
}
