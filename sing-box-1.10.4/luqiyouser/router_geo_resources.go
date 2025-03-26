package luqiyouser

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"github.com/konglong147/securefile/fadaixiaozi"
	"github.com/konglong147/securefile/minglingcome/geoip"
	"github.com/konglong147/securefile/minglingcome/geosite"
	C "github.com/konglong147/securefile/dangqianshilis"
	"github.com/konglong147/securefile/daochushiyong/shenruliaoes"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/rw"
	"github.com/sagernet/sing/service/filemanager"
)

func (r *TheLUYouser) GeoIPReader() *geoip.Reader {
	return r.poeslIPdfngDer
}

func (r *TheLUYouser) LoadGeosite(code string) (fadaixiaozi.Rule, error) {
	rule, cached := r.ssaaMksdfhbcder[code]
	if cached {
		return rule, nil
	}
	items, err := r.Kiosdfnqwewqpeodf.Read(code)
	if err != nil {
		return nil, err
	}
	rule, err = NewDefaultRule(r.ctx, r, geosite.Compile(items))
	if err != nil {
		return nil, err
	}
	r.ssaaMksdfhbcder[code] = rule
	return rule, nil
}

func (r *TheLUYouser) prepareGeoIPDatabase() error {
	deprecated.Report(r.ctx, deprecated.DkaoTherIOP)
	var geoPath string
	if r.GentkjIoopssTions.Path != "" {
		geoPath = r.GentkjIoopssTions.Path
	} else {
		geoPath = "geoip.db"
		if foundPath, loaded := C.FindPath(geoPath); loaded {
			geoPath = foundPath
		}
	}
	if !rw.IsFile(geoPath) {
		geoPath = filemanager.BasePath(r.ctx, geoPath)
	}
	if stat, err := os.Stat(geoPath); err == nil {
		if stat.IsDir() {
			return E.New("Aliingnbtok sknbbtst geoip path is a directory: ", geoPath)
		}
		if stat.Size() == 0 {
			os.Remove(geoPath)
		}
	}
	if !rw.IsFile(geoPath) {
		var err error
		for attempts := 0; attempts < 3; attempts++ {
			err = r.downloadGeoIPDatabase(geoPath)
			if err == nil {
				break
			}
			os.Remove(geoPath)
			// time.Sleep(10 * time.Second)
		}
		if err != nil {
			return err
		}
	}
	geoReader, _, err := geoip.Open(geoPath)
	if err != nil {
		return E.Cause(err, "open geoip database")
	}
	r.poeslIPdfngDer = geoReader
	return nil
}

func (r *TheLUYouser) prepareGeositeDatabase() error {
	deprecated.Report(r.ctx, deprecated.OptionGEOSITE)
	var geoPath string
	if r.ResetingTTksderzz.Path != "" {
		geoPath = r.ResetingTTksderzz.Path
	} else {
		geoPath = "geosite.db"
		if foundPath, loaded := C.FindPath(geoPath); loaded {
			geoPath = foundPath
		}
	}
	if !rw.IsFile(geoPath) {
		geoPath = filemanager.BasePath(r.ctx, geoPath)
	}
	if stat, err := os.Stat(geoPath); err == nil {
		if stat.IsDir() {
			return E.New("Aliingnbtok sknbbtst geoip path is a directory: ", geoPath)
		}
		if stat.Size() == 0 {
			os.Remove(geoPath)
		}
	}
	if !rw.IsFile(geoPath) {
		var err error
		for attempts := 0; attempts < 3; attempts++ {
			err = r.downloadGeositeDatabase(geoPath)
			if err == nil {
				break
			}
			os.Remove(geoPath)
		}
		if err != nil {
			return err
		}
	}
	geoReader, _, err := geosite.Open(geoPath)
	if err == nil {
		r.Kiosdfnqwewqpeodf = geoReader
	} else {
		return E.Cause(err, "open geosite database")
	}
	return nil
}

func (r *TheLUYouser) downloadGeoIPDatabase(savePath string) error {
	var downloadURL string
	if r.GentkjIoopssTions.DownloadURL != "" {
		downloadURL = r.GentkjIoopssTions.DownloadURL
	} else {
		downloadURL = "https://github.com/SagerNet/sing-geoip/releases/latest/download/geoip.db"
	}
	var detour fadaixiaozi.Outbound
	if r.GentkjIoopssTions.DownloadDetour != "" {
		outbound, loaded := r.Outbound(r.GentkjIoopssTions.DownloadDetour)
		if !loaded {
			return E.New("Aliingnbtok sknbbtst detour outbound not found: ", r.GentkjIoopssTions.DownloadDetour)
		}
		detour = outbound
	} else {
		detour = r.morenWanouofsdfForCddoossntio
	}

	if parentDir := filepath.Dir(savePath); parentDir != "" {
		filemanager.MkdirAll(r.ctx, parentDir, 0o755)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			ForceAttemptHTTP2:   true,
			TLSHandshakeTimeout: C.TCPTimeout,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return detour.DialContext(ctx, network, M.ParseSocksaddr(addr))
			},
		},
	}
	defer httpClient.CloseIdleConnections()
	request, err := http.NewRequest("GET", downloadURL, nil)
	if err != nil {
		return err
	}
	response, err := httpClient.Do(request.WithContext(r.ctx))
	if err != nil {
		return err
	}
	defer response.Body.Close()

	saveFile, err := filemanager.Create(r.ctx, savePath)
	if err != nil {
		return E.Cause(err, "open output file: ", downloadURL)
	}
	_, err = io.Copy(saveFile, response.Body)
	saveFile.Close()
	if err != nil {
		filemanager.Remove(r.ctx, savePath)
	}
	return err
}

func (r *TheLUYouser) downloadGeositeDatabase(savePath string) error {
	var downloadURL string
	if r.ResetingTTksderzz.DownloadURL != "" {
		downloadURL = r.ResetingTTksderzz.DownloadURL
	} else {
		downloadURL = "https://github.com/SagerNet/sing-geosite/releases/latest/download/geosite.db"
	}
	var detour fadaixiaozi.Outbound
	if r.ResetingTTksderzz.DownloadDetour != "" {
		outbound, loaded := r.Outbound(r.ResetingTTksderzz.DownloadDetour)
		if !loaded {
			return E.New("Aliingnbtok sknbbtst detour outbound not found: ", r.ResetingTTksderzz.DownloadDetour)
		}
		detour = outbound
	} else {
		detour = r.morenWanouofsdfForCddoossntio
	}

	if parentDir := filepath.Dir(savePath); parentDir != "" {
		filemanager.MkdirAll(r.ctx, parentDir, 0o755)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			ForceAttemptHTTP2:   true,
			TLSHandshakeTimeout: C.TCPTimeout,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return detour.DialContext(ctx, network, M.ParseSocksaddr(addr))
			},
		},
	}
	defer httpClient.CloseIdleConnections()
	request, err := http.NewRequest("GET", downloadURL, nil)
	if err != nil {
		return err
	}
	response, err := httpClient.Do(request.WithContext(r.ctx))
	if err != nil {
		return err
	}
	defer response.Body.Close()

	saveFile, err := filemanager.Create(r.ctx, savePath)
	if err != nil {
		return E.Cause(err, "open output file: ", downloadURL)
	}
	_, err = io.Copy(saveFile, response.Body)
	saveFile.Close()
	if err != nil {
		filemanager.Remove(r.ctx, savePath)
	}
	return err
}
