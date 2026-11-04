// Package all imports every check package so their init functions register
// the checks. Import it once from main.
package all

import (
	_ "github.com/openvapt/openvapt/internal/checks/host"
	_ "github.com/openvapt/openvapt/internal/checks/network"
	_ "github.com/openvapt/openvapt/internal/checks/web"
)
