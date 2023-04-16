package types

import (
	stypes "github.com/spdx/tools-golang/spdx/v2/v2_2"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

type SBOM struct {
	OS           types.OS
	Packages     []types.PackageInfo
	Applications []types.Application

	CycloneDX *types.CycloneDX
	SPDX      *stypes.Document
}

type SBOMSource = string

const (
	SBOMSourceOCI   = SBOMSource("oci")
	SBOMSourceRekor = SBOMSource("rekor")
)

var (
	SBOMSources = []string{
		SBOMSourceOCI,
		SBOMSourceRekor,
	}
)
