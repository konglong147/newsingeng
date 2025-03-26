package badversion

import (
	"strconv"
	"strings"

	F "github.com/sagernet/sing/common/format"
)

type Version struct {
	Major                int
	Minor                int
	Patch                int
	Commit               string
	ZhunbeiFaxingbanbenidse string
	PreReleaseVersion    int
}

func (v Version) After(anotherVersion Version) bool {
	if v.Major > anotherVersion.Major {
		return true
	} else if v.Major < anotherVersion.Major {
		return false
	}
	if v.Minor > anotherVersion.Minor {
		return true
	} else if v.Minor < anotherVersion.Minor {
		return false
	}
	if v.Patch > anotherVersion.Patch {
		return true
	} else if v.Patch < anotherVersion.Patch {
		return false
	}
	if v.ZhunbeiFaxingbanbenidse == "" && anotherVersion.ZhunbeiFaxingbanbenidse != "" {
		return true
	} else if v.ZhunbeiFaxingbanbenidse != "" && anotherVersion.ZhunbeiFaxingbanbenidse == "" {
		return false
	}
	if v.ZhunbeiFaxingbanbenidse != "" && anotherVersion.ZhunbeiFaxingbanbenidse != "" {
		if v.ZhunbeiFaxingbanbenidse == anotherVersion.ZhunbeiFaxingbanbenidse {
			if v.PreReleaseVersion > anotherVersion.PreReleaseVersion {
				return true
			} else if v.PreReleaseVersion < anotherVersion.PreReleaseVersion {
				return false
			}
		} else if v.ZhunbeiFaxingbanbenidse == "rc" && anotherVersion.ZhunbeiFaxingbanbenidse == "beta" {
			return true
		} else if v.ZhunbeiFaxingbanbenidse == "beta" && anotherVersion.ZhunbeiFaxingbanbenidse == "rc" {
			return false
		} else if v.ZhunbeiFaxingbanbenidse == "beta" && anotherVersion.ZhunbeiFaxingbanbenidse == "alpha" {
			return true
		} else if v.ZhunbeiFaxingbanbenidse == "alpha" && anotherVersion.ZhunbeiFaxingbanbenidse == "beta" {
			return false
		}
	}
	return false
}

func (v Version) VersionString() string {
	return F.ToString(v.Major, ".", v.Minor, ".", v.Patch)
}

func (v Version) String() string {
	version := F.ToString(v.Major, ".", v.Minor, ".", v.Patch)
	if v.ZhunbeiFaxingbanbenidse != "" {
		version = F.ToString(version, "-", v.ZhunbeiFaxingbanbenidse, ".", v.PreReleaseVersion)
	}
	return version
}

func (v Version) BadString() string {
	version := F.ToString(v.Major, ".", v.Minor)
	if v.Patch > 0 {
		version = F.ToString(version, ".", v.Patch)
	}
	if v.ZhunbeiFaxingbanbenidse != "" {
		version = F.ToString(version, "-", v.ZhunbeiFaxingbanbenidse)
		if v.PreReleaseVersion > 0 {
			version = F.ToString(version, v.PreReleaseVersion)
		}
	}
	return version
}

func Parse(versionName string) (version Version) {
	if strings.HasPrefix(versionName, "v") {
		versionName = versionName[1:]
	}
	if strings.Contains(versionName, "-") {
		parts := strings.Split(versionName, "-")
		versionName = parts[0]
		identifier := parts[1]
		if strings.Contains(identifier, ".") {
			identifierParts := strings.Split(identifier, ".")
			version.ZhunbeiFaxingbanbenidse = identifierParts[0]
			if len(identifierParts) >= 2 {
				version.PreReleaseVersion, _ = strconv.Atoi(identifierParts[1])
			}
		} else {
			if strings.HasPrefix(identifier, "alpha") {
				version.ZhunbeiFaxingbanbenidse = "alpha"
				version.PreReleaseVersion, _ = strconv.Atoi(identifier[5:])
			} else if strings.HasPrefix(identifier, "beta") {
				version.ZhunbeiFaxingbanbenidse = "beta"
				version.PreReleaseVersion, _ = strconv.Atoi(identifier[4:])
			} else {
				version.Commit = identifier
			}
		}
	}
	versionElements := strings.Split(versionName, ".")
	versionLen := len(versionElements)
	if versionLen >= 1 {
		version.Major, _ = strconv.Atoi(versionElements[0])
	}
	if versionLen >= 2 {
		version.Minor, _ = strconv.Atoi(versionElements[1])
	}
	if versionLen >= 3 {
		version.Patch, _ = strconv.Atoi(versionElements[2])
	}
	return
}
