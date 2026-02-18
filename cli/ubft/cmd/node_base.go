package cmd

import (
	"github.com/spf13/cobra"
)

type (
	p2pFlags struct {
		Address                    string
		AnnounceAddresses          []string
		BootstrapAddresses         []string // bootstrap addresses (libp2p multiaddress format)
		BootstrapConnectRetryCount int
		BootstrapConnectRetryDelay int
	}
)

func (f *p2pFlags) addP2PFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&f.Address, "address", "a", "/ip4/127.0.0.1/tcp/26652", "listen address for p2p connections (libp2p multiaddress format)")
	cmd.Flags().StringSliceVarP(&f.AnnounceAddresses, "announce-addresses", "", nil, "announced listen addresses (libp2p multiaddress format)")
	cmd.Flags().StringSliceVar(&f.BootstrapAddresses, "bootnodes", nil, "addresses of bootstrap nodes (libp2p multiaddress format)")
	cmd.Flags().IntVar(&f.BootstrapConnectRetryCount, "bootnode-connect-retry-count", 10, "number of times to retry connecting to bootstrap nodes")
	cmd.Flags().IntVar(&f.BootstrapConnectRetryDelay, "bootnode-connect-retry-delay", 1, "delay in seconds between retries for connecting to bootstrap nodes")
}

func hideFlags(cmd *cobra.Command, flags ...string) {
	for _, flag := range flags {
		if err := cmd.Flags().MarkHidden(flag); err != nil {
			panic(err)
		}
	}
}
