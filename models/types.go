package models

type PackageDetails struct {
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	Commit    string    `json:"commit,omitempty"`
	Ecosystem Ecosystem `json:"ecosystem,omitempty"`
	CompareAs Ecosystem `json:"compareAs,omitempty"`
}

type PackageDetailsParser = func(pathToLockfile string) ([]PackageDetails, error)

const AlpineEcosystem Ecosystem = "Alpine"
const DebianEcosystem Ecosystem = "Debian"
const CargoEcosystem Ecosystem = "crates.io"
const ComposerEcosystem Ecosystem = "Packagist"
const ConanEcosystem Ecosystem = "ConanCenter"
const BundlerEcosystem Ecosystem = "RubyGems"
const GoEcosystem Ecosystem = "Go"
const MavenEcosystem Ecosystem = "Maven"
const MixEcosystem Ecosystem = "Hex"
const NpmEcosystem Ecosystem = "npm"
const NuGetEcosystem Ecosystem = "NuGet"
const PubEcosystem Ecosystem = "Pub"
const PipEcosystem Ecosystem = "PyPI"
