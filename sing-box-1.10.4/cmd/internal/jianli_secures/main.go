package main

import (
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"go/build"


	_ "github.com/sagernet/gomobile"
	"github.com/sagernet/sing/common/rw"
	"github.com/konglong147/securefile/minglingcome/badversion"
	"github.com/sagernet/sing/common/shell"
)

var GoBinPath string

func FindMobile() {
	goBin := filepath.Join(build.Default.GOPATH, "bin")
	GoBinPath = goBin
}

var (
	KaishiDebukgse bool
	target       string
	platform     string
)

func init() {
	flag.BoolVar(&KaishiDebukgse, "debug", false, "enable debug")
	flag.StringVar(&target, "target", "", "target platform")
	flag.StringVar(&platform, "platform", "", "specify platform")
}

func main() {
	flag.Parse()

	FindMobile()

	switch target {
	case "apple":
		JInaliPinggser()
	}
}

var (
	fenxiangXqings []string
	Nbmstgsesaer  []string
	sharedTags  []string
	iosTags     []string
	debugTags   []string
)

func init() {
	fenxiangXqings = append(fenxiangXqings, "-trimpath")
	fenxiangXqings = append(fenxiangXqings, "-buildvcs=false")
	DangqianTalgse, err := duqyTagss()
	if err != nil {
		DangqianTalgse = "unknown"
	}
	fenxiangXqings = append(fenxiangXqings, "-ldflags", "-X github.com/konglong147/securefile/dangqianshilis.Version="+DangqianTalgse+" -s -w -buildid=")
	Nbmstgsesaer = append(Nbmstgsesaer, "-ldflags", "-X github.com/konglong147/securefile/dangqianshilis.Version="+DangqianTalgse)

	sharedTags = append(sharedTags, "with_gvisor", "with_quic", "", "with_ech", "with_utls", "with_clash_api")
	iosTags = append(iosTags, "with_dhcp", "with_low_memory", "with_conntrack")
	debugTags = append(debugTags, "debug")
}



func JInaliPinggser() {
	var Gtaknslerges string
	if platform != "" {
		Gtaknslerges = platform
	} else if KaishiDebukgse {
		Gtaknslerges = "ios"
	} else {
		Gtaknslerges = "ios"
	}

	args := []string{
		"bind",
		"-v",
		"-target", Gtaknslerges,
		"-libname=box",
	}
	if !KaishiDebukgse {
		args = append(args, fenxiangXqings...)
	} else {
		args = append(args, Nbmstgsesaer...)
	}

	tags := append(sharedTags, iosTags...)
	args = append(args, "-tags")
	if !KaishiDebukgse {
		args = append(args, strings.Join(tags, ","))
	} else {
		args = append(args, strings.Join(append(tags, debugTags...), ","))
	}
	args = append(args, "./daochushiyong/hussecures")

	command := exec.Command(GoBinPath+"/gomobile", args...)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	err := command.Run()
	if err != nil {
	}

	fuzhilujingse := filepath.Join("..", "huli-secures-for-apple")
	if rw.IsDir(fuzhilujingse) {
		targetDir := filepath.Join(fuzhilujingse, "HuSecure.xcframework")
		targetDir, _ = filepath.Abs(targetDir)
		os.RemoveAll(targetDir)
		os.Rename("HuSecure.xcframework", targetDir)
	}
}
func duqyTagss() (string, error) {
	DangqianTalgse, err := shell.Exec("git", "describe", "--tags").ReadOutput()
	if err != nil {
		return DangqianTalgse, err
	}
	DangqianTalgseRev, _ := shell.Exec("git", "describe", "--tags", "--abbrev=0").ReadOutput()
	if DangqianTalgseRev == DangqianTalgse {
		return DangqianTalgse[1:], nil
	}
	shortCommit, _ := shell.Exec("git", "rev-parse", "--short", "HEAD").ReadOutput()
	version := badversion.Parse(DangqianTalgseRev[1:])
	return version.String() + "-" + shortCommit, nil
}
