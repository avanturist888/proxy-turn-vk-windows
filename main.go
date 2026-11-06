//go:build !linux

package main

import (
	"embed"
	"os"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/linux"
	"github.com/wailsapp/wails/v2/pkg/options/windows"

	"wdtt-desktop/backend"
)

//go:embed all:frontend/dist
var assets embed.FS

//go:embed assets/server/deploy.sh
var deployScript []byte

//go:embed assets/server/wdtt-server
var serverBinary []byte

//go:embed assets/icons/icon.png
var trayIcon []byte

func main() {
	// Без прав администратора туннель не поднять: передаём запуск задаче
	// планировщика (без UAC) или уже запущенному окну.
	backend.RequestConnectIfFlagged(os.Args[1:])
	if backend.HandOffIfNotElevated() {
		return
	}
	backend.InstallCrashLog()
	backend.Init(deployScript, serverBinary)
	app := backend.NewApp(trayIcon)

	err := wails.Run(&options.App{
		Title:     "WDTT",
		Width:     900,
		Height:    600,
		MinWidth:  800,
		MinHeight: 550,
		Frameless: false,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 255, G: 255, B: 255, A: 1},
		OnStartup:        app.Startup,
		OnShutdown:       app.Shutdown,
		OnBeforeClose:    app.OnBeforeClose,
		SingleInstanceLock: &options.SingleInstanceLock{
			UniqueId:               "wdtt-desktop-3f6c2a1e",
			OnSecondInstanceLaunch: func(options.SecondInstanceData) { app.OnSecondInstance() },
		},
		Bind:             []interface{}{app},
		Windows: &windows.Options{
			WebviewIsTransparent: false,
			WindowIsTranslucent:  false,
		},
		Linux: &linux.Options{
			ProgramName: "WDTT",
		},
	})
	if err != nil {
		panic(err)
	}
}

