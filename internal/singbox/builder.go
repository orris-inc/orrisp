// Package singbox provides sing-box service management.
// This file re-exports functions from the builder subpackage for backward compatibility.
package singbox

import (
	"github.com/easayliu/orrisp/internal/api"
	"github.com/easayliu/orrisp/internal/singbox/builder"
	"github.com/sagernet/sing-box/option"
)

// BuildConfig generates sing-box configuration based on node config and subscription list.
// This is a wrapper around builder.BuildConfig for backward compatibility.
func BuildConfig(nodeConfig *api.NodeConfig, subscriptions []api.Subscription, clashAPIAddr string) (*option.Options, error) {
	return builder.BuildConfig(nodeConfig, subscriptions, clashAPIAddr)
}
