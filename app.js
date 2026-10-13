/* Sentinel DRPP — front-end demonstration only. No real threat intelligence is queried. */
(() => {
  "use strict";
  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
  const STORE = {
    scans: "sentinel_scans_v1", alerts: "sentinel_alerts_v1", theme: "sentinel_theme_v1",
    profile: "sentinel_profile_v1", notifications: "sentinel_notifications_v1",
    banner: "sentinel_banner_dismissed_v1", checklist: "sentinel_checklist_v1"
  };
  const safeRead = (key, fallback) => { try { const value = localStorage.getItem(key); return value ? JSON.parse(value) : fallback; } catch { return fallback; } };
  const safeWrite = (key, value) => { try { localStorage.setItem(key, JSON.stringify(value)); } catch { toast("Browser storage is unavailable; changes may not persist."); } };
  const escapeText = value => String(value ?? "").replace(/[&<>"']/g, ch => ({ "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;" }[ch]));
  const dateText = value => { const d = new Date(value); return Number.isNaN(d.getTime()) ? "—" : d.toLocaleString([], {month:"short", day:"numeric", hour:"2-digit", minute:"2-digit"}); };
  const dayText = value => { const d = new Date(value); return Number.isNaN(d.getTime()) ? "—" : d.toLocaleDateString([], {month:"short",day:"numeric"}); };
  let toastTimer = null;
  function toast(message) {
    if (safeRead(STORE.notifications, true) === false) return;
    const region = $("#toast-region"); if (!region) return;
    const node = document.createElement("div"); node.className = "toast"; node.textContent = message;
    region.append(node); setTimeout(() => node.remove(), 3300);
  }
  const riskLevel = score => score < 30 ? "Low" : score < 60 ? "Medium" : score < 80 ? "High" : "Critical";
  const riskClass = level => String(level).toLowerCase().replace(/[^a-z]/g, "");
  const iconForRisk = level => level === "Low" ? "✓" : level === "Medium" ? "⌁" : "!";
  const defaultScans = [
    {id:"demo-1",url:"https://example.com",host:"example.com",score:12,level:"Low",reasons:["Uses HTTPS.","No obvious deceptive URL pattern was detected by this basic demo check."],createdAt:new Date(Date.now()-1000*60*28).toISOString(),demo:true},
    {id:"demo-2",url:"http://account-verify-example.invalid/login",host:"account-verify-example.invalid",score:68,level:"High",reasons:["Uses HTTP rather than HTTPS.","Contains a login/verification keyword combination.","The .invalid domain is reserved for examples and is not a real target."],createdAt:new Date(Date.now()-1000*60*90).toISOString(),demo:true},
    {id:"demo-3",url:"https://docs.example.org",host:"docs.example.org",score:24,level:"Low",reasons:["Uses HTTPS.","No obvious high-risk pattern was detected by this basic demo check."],createdAt:new Date(Date.now()-1000*60*60*5).toISOString(),demo:true},
    {id:"demo-4",url:"http://192.0.2.10/sign-in",host:"192.0.2.10",score:83,level:"Critical",reasons:["Uses HTTP rather than HTTPS.","Uses an IP address as the hostname.","Contains a sign-in keyword."],createdAt:new Date(Date.now()-1000*60*60*20).toISOString(),demo:true},
    {id:"demo-5",url:"https://news.example.net",host:"news.example.net",score:31,level:"Medium",reasons:["A basic heuristic raised a minor structural concern."],createdAt:new Date(Date.now()-1000*60*60*29).toISOString(),demo:true}
  ];
  const defaultAlerts = [
    {id:"a1",title:"Possible credential-harvesting pattern",description:"A sample URL contains login-related wording and an unusual domain pattern. Verify the destination independently before entering credentials.",severity:"Critical",type:"Phishing",time:new Date(Date.now()-1000*60*16).toISOString(),read:false,demo:true},
    {id:"a2",title:"Unencrypted sample destination",description:"A demonstration URL uses HTTP. Avoid sharing sensitive information over unencrypted connections.",severity:"High",type:"Suspicious domain",time:new Date(Date.now()-1000*60*54).toISOString(),read:false,demo:true},
    {id:"a3",title:"Security hygiene reminder",description:"Review multi-factor authentication and password uniqueness for important accounts.",severity:"Medium",type:"Account security",time:new Date(Date.now()-1000*60*60*3).toISOString(),read:false,demo:true}
  ];
  let scans = safeRead(STORE.scans, null);
  if (!Array.isArray(scans)) { scans = defaultScans.slice(); safeWrite(STORE.scans, scans); }
  let alerts = safeRead(STORE.alerts, null);
  if (!Array.isArray(alerts)) { alerts = defaultAlerts.slice(); safeWrite(STORE.alerts, alerts); }
  let activePage = "overview", riskChart = null, activityChart = null;

  const threats = [
    {id:"t1",title:"Credential-harvesting page",domain:"login-check.example.invalid",type:"Phishing",severity:"Critical",icon:"⚑",description:"An educational example of a page that imitates an account sign-in and pressures visitors to confirm credentials.",indicators:["Unexpected login prompt from an unsolicited message","Domain differs from the official service","Urgent wording or threats of account suspension"],recommendation:"Navigate to the official service by typing its known address or using a trusted bookmark."},
    {id:"t2",title:"Lookalike brand domain",domain:"paypaI.example.invalid",type:"Brand impersonation",severity:"High",icon:"◇",description:"This sample illustrates how a lookalike string can imitate a familiar brand name.",indicators:["Subtle character substitutions","Unfamiliar domain ending","Unexpected request for payment or personal data"],recommendation:"Inspect the complete registered domain and verify through an independent channel."},
    {id:"t3",title:"Exposed information reminder",domain:"sample-public-record.example",type:"Data exposure",severity:"Medium",icon:"⌑",description:"A fictional record used to explain why publicly shared documents can reveal more information than intended.",indicators:["Public links with broad access","Personal details in document metadata","Shared files without an expiry or access review"],recommendation:"Review sharing permissions and remove sensitive details before publishing."},
    {id:"t4",title:"Unusual subdomain pattern",domain:"secure.account.verify.example.invalid",type:"Suspicious domain",severity:"High",icon:"⌁",description:"Nested subdomains can be confusing. Subdomain count alone does not establish malicious intent.",indicators:["Long or confusing hostname","Unexpected redirects reported by a trusted scanner","Link differs from the expected official domain"],recommendation:"Compare the registrable domain with the organization's official website."},
    {id:"t5",title:"Unexpected attachment prompt",domain:"invoice-preview.example.invalid",type:"Phishing",severity:"Medium",icon:"▤",description:"A fictional email lure that asks the recipient to download an unexpected invoice attachment.",indicators:["Unsolicited invoice","Pressure to enable macros or bypass warnings","Sender address does not match the claimed organization"],recommendation:"Confirm the invoice with the sender using a known contact method."},
    {id:"t6",title:"Public profile privacy check",domain:"public-profile.example",type:"Data exposure",severity:"Low",icon:"◎",description:"A reminder to review what personal details are visible on public profiles and social networks.",indicators:["Home address or phone number is public","Birth date or recovery clues are widely visible","Old public posts contain sensitive details"],recommendation:"Review privacy settings and limit personal details that could support account recovery attacks."}
  ];
  const recommendations = [
    {id:"r1",icon:"⌑",title:"Enable multi-factor authentication",description:"Add an extra verification step to email, banking, and social accounts, especially for administrator access.",priority:"High"},
    {id:"r2",icon:"⚿",title:"Use unique passwords",description:"Use a password manager to create long, unique passwords instead of reusing the same password.",priority:"High"},
    {id:"r3",icon:"⌕",title:"Verify links before clicking",description:"Check the full domain and sender. If a message feels urgent or unusual, visit the service directly.",priority:"High"},
    {id:"r4",icon:"↻",title:"Keep software updated",description:"Turn on automatic security updates for your browser, operating system, and important applications.",priority:"Medium"},
    {id:"r5",icon:"◈",title:"Review privacy and sharing",description:"Check public profiles, file-sharing links, app permissions, and recovery information for unnecessary exposure.",priority:"Medium"},
    {id:"r6",icon:"▤",title:"Download from trusted sources",description:"Avoid unexpected attachments and install software only from official stores or vendor websites.",priority:"Medium"}
  ];
  function goTo(page) {
    const target = $(`#page-${page}`);
    if (!target) return;
    activePage = page;
    $$(".page").forEach(el => el.classList.toggle("active", el === target));
    $$(".nav-item[data-page]").forEach(el => el.classList.toggle("active", el.dataset.page === page));
    const activeNav = $(`.nav-item[data-page="${page}"]`);
    $("#page-breadcrumb").textContent = activeNav ? activeNav.textContent.trim().replace(/\s+\d+$/, "") : page;
    $("#sidebar").classList.remove("open");
    if (page === "overview") renderDashboard();
    if (page === "scanner") renderScanTable("#scanner-history-body", scans.slice(0,5), false);
    if (page === "threats") renderThreats();
    if (page === "alerts") renderAlerts();
    if (page === "history") renderHistory();
    if (page === "recommendations") renderRecommendations();
    if (page === "settings") syncSettings();
    window.scrollTo({top:0,behavior:"smooth"});
  }
  function createScanRow(scan, actions = true) {
    const tr = document.createElement("tr");
    const level = scan.level || riskLevel(scan.score);
    const url = escapeText(scan.url);
    tr.innerHTML = `<td><div class="domain-cell"><span class="domain-icon">↗</span><span class="domain-text" title="${url}">${url}<small>${escapeText(scan.demo ? "Demo / heuristic" : "Local demo heuristic")}</small></span></div></td><td class="score-cell">${Number(scan.score)} / 100</td><td><span class="risk-pill ${riskClass(level)}">${escapeText(level)}</span></td><td>${escapeText(dateText(scan.createdAt))}</td><td>${actions ? `<button class="row-action" data-scan-detail="${escapeText(scan.id)}" aria-label="View scan details">···</button>` : ""}</td>`;
    return tr;
  }
  function renderScanTable(selector, list, actions = true) {
    const body = $(selector); if (!body) return;
    body.replaceChildren(...list.map(scan => createScanRow(scan, actions)));
  }
  function scanDetail(id) {
    const scan = scans.find(item => item.id === id); if (!scan) return;
    showDialog(`<div class="dialog-detail"><h2>${escapeText(scan.host || scan.url)}</h2><p>This is a local demonstration result from transparent URL heuristics. It is not a verified threat verdict.</p><div class="detail-meta"><span>Risk score: ${scan.score}/100</span><span class="risk-pill ${riskClass(scan.level)}">${escapeText(scan.level)}</span><span>${escapeText(dateText(scan.createdAt))}</span></div><h3>Indicators reviewed</h3><ul>${(scan.reasons || []).map(r => `<li>${escapeText(r)}</li>`).join("")}</ul><p><b>Recommendation:</b> Confirm the destination through a trusted channel. Do not enter sensitive details if you are unsure.</p></div>`);
  }
  function showDialog(html) { const dialog = $("#detail-dialog"); $("#dialog-content").innerHTML = html; if (typeof dialog.showModal === "function") dialog.showModal(); else toast("Details are unavailable in this browser."); }
  function renderDashboard() {
    const total = scans.length + 123;
    const avg = scans.length ? Math.round(scans.reduce((sum,s)=>sum+s.score,0)/scans.length) : 0;
    $("#total-scans").textContent = total;
    $("#donut-total").textContent = total;
    $("#overall-score").textContent = avg || 38;
    $("#overall-progress").style.width = `${avg || 38}%`;
    const counts = {Low:83,Medium:29,High:10,Critical:6};
    scans.forEach(s => { counts[s.level] = (counts[s.level] || 0) + 1; });
    $("#safe-count").textContent = counts.Low;
    $("#medium-count").textContent = counts.Medium;
    $("#high-count").textContent = counts.High + counts.Critical;
    $("#review-count").textContent = counts.High + counts.Critical;
    const openAlerts = alerts.filter(a=>!a.dismissed).length;
    $("#open-alert-count").textContent = openAlerts;
    $("#sidebar-alert-count").textContent = alerts.filter(a=>!a.dismissed&&!a.read).length;
    $("#top-alert-dot").style.display = alerts.some(a=>!a.read&&!a.dismissed) ? "block" : "none";
    renderScanTable("#recent-scans-body", scans.slice(0,5));
    $("#recent-empty").classList.toggle("hidden", scans.length > 0);
    renderDashboardAlerts();
    renderCharts([counts.Low,counts.Medium,counts.High+counts.Critical]);
  }
  function chartColors() {
    const css = getComputedStyle(document.body);
    return {text:css.getPropertyValue("--muted").trim()||"#8290a9",grid:css.getPropertyValue("--line").trim()||"#1e2c42"};
  }
  function renderCharts(values) {
    if (!window.Chart) return;
    const colors = chartColors();
    if (riskChart) riskChart.destroy();
    if (activityChart) activityChart.destroy();
    const riskCanvas = $("#riskChart"), activityCanvas = $("#activityChart");
    if (riskCanvas) riskChart = new Chart(riskCanvas, {type:"doughnut",data:{labels:["Low risk","Medium risk","High / critical"],datasets:[{data:values,backgroundColor:["#46e0d0","#9b82ff","#ffb65c"],borderWidth:0,hoverOffset:5}]},options:{responsive:true,maintainAspectRatio:false,cutout:"76%",plugins:{legend:{display:false},tooltip:{callbacks:{label:ctx=>`${ctx.label}: ${ctx.raw}`}}}}});
    if (activityCanvas) activityChart = new Chart(activityCanvas,{type:"line",data:{labels:["Mon","Tue","Wed","Thu","Fri","Sat","Sun"],datasets:[{label:"Scans",data:[18,25,16,34,28,41,Math.max(19,scans.length)],borderColor:"#46e0d0",backgroundColor:"rgba(70,224,208,.10)",fill:true,tension:.38,pointRadius:3,pointBackgroundColor:"#46e0d0",borderWidth:2}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{grid:{display:false},ticks:{color:colors.text,font:{size:9}}},y:{beginAtZero:true,grid:{color:colors.grid},ticks:{color:colors.text,font:{size:9},maxTicksLimit:5}}}}});
  }
  function renderDashboardAlerts() {
    const container = $("#dashboard-alerts"); if (!container) return;
    const list = alerts.filter(a=>!a.dismissed).slice(0,3);
    container.replaceChildren();
    list.forEach(a => {
      const div = document.createElement("div"); div.className="alert-preview-item";
      const icon = document.createElement("span"); icon.className=`alert-symbol ${riskClass(a.severity)}`; icon.textContent=iconForRisk(a.severity);
      const content=document.createElement("div"), title=document.createElement("b"), desc=document.createElement("p"), time=document.createElement("small");
      title.textContent=a.title; desc.textContent=a.description; time.textContent=`${dateText(a.time)} · Sample alert`;
      content.append(title,desc,time); div.append(icon,content); container.append(div);
    });
    if (!list.length) container.textContent="No open demo alerts.";
  }
  function analyzeUrl(raw) {
    let url;
    try { url = new URL(raw.includes("://") ? raw : `https://${raw}`); }
    catch { return {error:"Enter a valid website address, such as https://example.com."}; }
    if (!["http:","https:"].includes(url.protocol)) return {error:"Only http:// and https:// URLs can be reviewed."};
    if (!url.hostname || !url.hostname.includes(".") && url.hostname !== "localhost") return {error:"Enter a hostname such as example.com."};
    let score = 10, reasons=[];
    if (url.protocol === "http:") { score += 22; reasons.push("Uses HTTP rather than HTTPS; traffic may not be encrypted."); }
    else reasons.push("Uses HTTPS. This encrypts transport but does not prove the website is trustworthy.");
    const host=url.hostname.toLowerCase();
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) { score += 35; reasons.push("Uses an IP address as the hostname rather than a typical domain name."); }
    if (raw.length > 100) { score += 15; reasons.push("The submitted URL is unusually long."); }
    if ((host.match(/\./g)||[]).length >= 4) { score += 12; reasons.push("Contains multiple subdomain levels; inspect the registered domain carefully."); }
    const suspiciousWords = ["login","verify","secure","account","password","update","wallet","confirm","signin"];
    const hits=suspiciousWords.filter(word=>`${host}${url.pathname}`.toLowerCase().includes(word));
    if (hits.length) { score += Math.min(24,hits.length*8); reasons.push(`Contains potentially sensitive wording: ${hits.join(", ")}. These words can also appear on legitimate sites.`); }
    if (host.includes("xn--")) { score += 18; reasons.push("Contains an internationalized domain label; check for lookalike characters if the domain is unfamiliar."); }
    if (url.username || url.password) { score += 25; reasons.push("Contains user-information fields before the hostname, a pattern worth inspecting."); }
    if (host.endsWith(".invalid")) { score = Math.max(score, 65); reasons.push("Uses the reserved .invalid suffix, included here only for safe demonstration."); }
    score=Math.max(0,Math.min(100,score));
    if (!reasons.length) reasons.push("No listed warning pattern was found by this basic heuristic. This is not proof of safety.");
    return {url:url.href,host,score,level:riskLevel(score),reasons};
  }
  function runScan(raw) {
    const result=analyzeUrl(raw);
    const error=$("#scan-error"), progress=$("#scan-progress"), resultBox=$("#scan-result"), button=$("#scan-button");
    if (result.error) { error.textContent=result.error; return; }
    error.textContent=""; resultBox.classList.add("hidden"); progress.classList.remove("hidden"); button.disabled=true;
    const fill=$("#progress-fill"), percent=$("#progress-percent"); let n=0;
    const interval=setInterval(()=>{
      n+=20; fill.style.width=`${n}%`; percent.textContent=`${n}%`;
      if(n>=100){
        clearInterval(interval); progress.classList.add("hidden"); button.disabled=false;
        const scan={id:`scan-${Date.now()}-${Math.random().toString(36).slice(2,7)}`,url:result.url,host:result.host,score:result.score,level:result.level,reasons:result.reasons,createdAt:new Date().toISOString(),demo:true};
        scans.unshift(scan); scans=scans.slice(0,200); safeWrite(STORE.scans,scans);
        resultBox.classList.remove("hidden");
        resultBox.innerHTML=`<div class="result-header"><div class="result-score ${riskClass(scan.level)}">${scan.score}</div><div><h3>${escapeText(scan.level)} illustrative risk</h3><p>${escapeText(scan.host)}</p><span class="demo-tag">HEURISTIC DEMO · NOT VERIFIED</span></div></div><div class="result-indicators">${scan.reasons.map(reason=>`<div class="result-indicator"><span>•</span><span>${escapeText(reason)}</span></div>`).join("")}</div><div class="result-recommendation"><b>Recommended next step</b><br>Check the domain independently, avoid entering sensitive details when uncertain, and use a trusted threat intelligence service for a real verdict.</div><button class="button button-secondary button-small" id="view-new-scan" style="margin-top:14px">View saved report →</button>`;
        $("#view-new-scan").addEventListener("click",()=>scanDetail(scan.id));
        renderScanTable("#scanner-history-body",scans.slice(0,5),false); renderDashboard(); renderHistory();
        toast("Demo URL analysis complete. Result saved locally.");
      }
    },90);
  }
  function renderThreats() {
    const container=$("#threat-grid"); if(!container)return;
    const query=($("#threat-search")?.value||"").toLowerCase(), severity=$("#threat-severity")?.value||"all", type=$("#threat-type")?.value||"all";
    const filtered=threats.filter(t=>(severity==="all"||t.severity===severity)&&(type==="all"||t.type===type)&&`${t.title} ${t.domain} ${t.description} ${t.type}`.toLowerCase().includes(query));
    container.replaceChildren();
    filtered.forEach(t=>{
      const card=document.createElement("article");card.className="threat-card";
      card.innerHTML=`<div class="threat-card-top"><span class="threat-type-icon">${escapeText(t.icon)}</span><span class="severity-pill ${riskClass(t.severity)}">${escapeText(t.severity)}</span></div><h3>${escapeText(t.title)}</h3><div class="threat-domain">${escapeText(t.domain)}</div><p>${escapeText(t.description)}</p><div class="threat-card-bottom"><small>${escapeText(t.type)} · Sample</small><button class="threat-detail-button" data-threat-detail="${escapeText(t.id)}">View details →</button></div>`;
      container.append(card);
    });
    if(!filtered.length) container.innerHTML='<div class="empty-state">No sample threats match your filters.</div>';
  }
  function threatDetail(id) {
    const t=threats.find(item=>item.id===id);if(!t)return;
    showDialog(`<div class="dialog-detail"><h2>${escapeText(t.title)}</h2><p>${escapeText(t.description)}</p><div class="detail-meta"><span>${escapeText(t.type)}</span><span class="severity-pill ${riskClass(t.severity)}">${escapeText(t.severity)}</span><span>Educational sample</span></div><h3>Common indicators</h3><ul>${t.indicators.map(i=>`<li>${escapeText(i)}</li>`).join("")}</ul><p><b>Recommended action:</b> ${escapeText(t.recommendation)}</p><p>These records are fictional examples and do not identify verified malicious domains.</p></div>`);
  }
  function renderAlerts() {
    const container=$("#alert-list");if(!container)return;
    const q=($("#alert-search")?.value||"").toLowerCase(), sev=$("#alert-severity")?.value||"all", status=$("#alert-status")?.value||"all";
    const list=alerts.filter(a=>!a.dismissed&&(sev==="all"||a.severity===sev)&&(status==="all"||(status==="unread"?!a.read:a.read))&&`${a.title} ${a.description} ${a.type}`.toLowerCase().includes(q));
    container.replaceChildren();
    list.forEach(a=>{
      const card=document.createElement("article");card.className=`alert-card ${a.read?"":"unread"}`;
      card.innerHTML=`<span class="alert-card-icon ${riskClass(a.severity)}">${iconForRisk(a.severity)}</span><div class="alert-card-content"><div class="alert-card-title-row"><h3>${escapeText(a.title)}</h3><span class="severity-pill ${riskClass(a.severity)}">${escapeText(a.severity)}</span>${a.read?"":'<span class="status-dot info" title="Unread"></span>'}</div><p>${escapeText(a.description)}</p><small>${escapeText(dateText(a.time))} · ${escapeText(a.type)} · ${a.demo?"Sample alert":"Local alert"}</small></div><div class="alert-actions"><button data-alert-read="${escapeText(a.id)}">${a.read?"Mark unread":"Mark read"}</button><button class="dismiss-alert" data-alert-dismiss="${escapeText(a.id)}">Dismiss</button></div>`;
      container.append(card);
    });
    if(!list.length) container.innerHTML='<div class="panel empty-state">No alerts match your filters.</div>';
    const open=alerts.filter(a=>!a.dismissed), unread=open.filter(a=>!a.read);
    $("#critical-alert-count").textContent=open.filter(a=>a.severity==="Critical").length;
    $("#high-alert-count").textContent=open.filter(a=>a.severity==="High").length;
    $("#medium-alert-count").textContent=open.filter(a=>a.severity==="Medium").length;
    $("#unread-alert-count").textContent=unread.length;
    $("#sidebar-alert-count").textContent=unread.length;
    $("#top-alert-dot").style.display=unread.length?"block":"none";
    $("#open-alert-count").textContent=open.length;
    renderDashboardAlerts();
  }
  function renderHistory() {
    const q=($("#history-search")?.value||"").toLowerCase(), level=$("#history-level")?.value||"all";
    const list=scans.filter(s=>(level==="all"||s.level===level)&&`${s.url} ${s.host}`.toLowerCase().includes(q));
    const body=$("#history-body");if(body) {body.replaceChildren(...list.map(s=>createScanRow(s)));$("#history-empty").classList.toggle("hidden",list.length>0);}
    $("#history-total").textContent=scans.length;
    $("#history-average").textContent=scans.length?`${Math.round(scans.reduce((a,s)=>a+s.score,0)/scans.length)}/100`:"—";
    $("#history-high").textContent=scans.filter(s=>s.score>=60).length;
  }
  function exportCsv() {
    const rows=[["URL","Host","Score","Risk level","Created at","Demo","Indicators"],...scans.map(s=>[s.url,s.host,s.score,s.level,s.createdAt,"Yes",(s.reasons||[]).join(" | ")])];
    const csv=rows.map(row=>row.map(value=>`"${String(value??"").replace(/"/g,'""')}"`).join(",")).join("\r\n");
    const blob=new Blob(["\ufeff"+csv],{type:"text/csv;charset=utf-8;"}), url=URL.createObjectURL(blob);
    const a=document.createElement("a");a.href=url;a.download="sentinel-scan-history.csv";document.body.append(a);a.click();a.remove();URL.revokeObjectURL(url);toast("CSV export prepared.");
  }
  function clearHistory() {
    if(!confirm("Clear all saved scan history from this browser? This cannot be undone."))return;
    scans=[];safeWrite(STORE.scans,scans);renderHistory();renderDashboard();renderScanTable("#scanner-history-body",[],false);toast("Scan history cleared.");
  }
  function renderRecommendations() {
    const container=$("#recommendation-grid");if(!container)return;
    const checked=safeRead(STORE.checklist,[]);
    container.replaceChildren();
    recommendations.forEach(r=>{
      const label=document.createElement("label");label.className=`recommendation-card ${checked.includes(r.id)?"completed":""}`;
      label.innerHTML=`<div class="recommendation-card-top"><span class="recommendation-icon">${escapeText(r.icon)}</span><span class="severity-pill ${r.priority==="High"?"high":"medium"}">${escapeText(r.priority)} priority</span></div><h3>${escapeText(r.title)}</h3><p>${escapeText(r.description)}</p><label><input type="checkbox" data-recommendation="${escapeText(r.id)}" ${checked.includes(r.id)?"checked":""}><span>${checked.includes(r.id)?"Completed":"Mark as completed"}</span></label>`;
      // Nested label is invalid HTML; normalize into a div-based card instead.
      const card=document.createElement("article");card.className=`recommendation-card ${checked.includes(r.id)?"completed":""}`;
      card.innerHTML=`<div class="recommendation-card-top"><span class="recommendation-icon">${escapeText(r.icon)}</span><span class="severity-pill ${r.priority==="High"?"high":"medium"}">${escapeText(r.priority)} priority</span></div><h3>${escapeText(r.title)}</h3><p>${escapeText(r.description)}</p><label><input type="checkbox" data-recommendation="${escapeText(r.id)}" ${checked.includes(r.id)?"checked":""}><span>${checked.includes(r.id)?"Completed":"Mark as completed"}</span></label>`;
      container.append(card);
    });
    const count=checked.length;$("#recommendation-progress").style.width=`${count/recommendations.length*100}%`;$("#recommendation-progress-label").textContent=`${count} of ${recommendations.length} completed`;
  }
  function syncSettings() {
    const profile=safeRead(STORE.profile,{name:"Demo Analyst",email:""});
    $("#profile-name").value=profile.name||"Demo Analyst";$("#profile-email").value=profile.email||"";
    $("#profile-name-side").textContent=profile.name||"Demo Analyst";$("#welcome-name").textContent=(profile.name||"Analyst").split(" ")[0];
    const light=document.body.classList.contains("light-theme");$("#theme-setting").checked=light;$("#notifications-setting").checked=safeRead(STORE.notifications,true);
  }
  function setTheme(light) {
    document.body.classList.toggle("light-theme",light);safeWrite(STORE.theme,light?"light":"dark");
    $("#theme-setting").checked=light;
    if(activePage==="overview")renderDashboard();
  }
  function resetDemo() {
    if(!confirm("Reset demo data, scan history, alerts, and preferences to their original sample state?"))return;
    scans=defaultScans.slice();alerts=defaultAlerts.slice();safeWrite(STORE.scans,scans);safeWrite(STORE.alerts,alerts);safeWrite(STORE.theme,"dark");safeWrite(STORE.profile,{name:"Demo Analyst",email:""});safeWrite(STORE.notifications,true);safeWrite(STORE.checklist,[]);
    document.body.classList.remove("light-theme");syncSettings();renderDashboard();renderAlerts();renderHistory();renderRecommendations();toast("Demo data has been reset.");
  }
  function init() {
    const loginForm = $("#login-form");
    if (loginForm) {
      loginForm.addEventListener("submit", event => {
        event.preventDefault();
        const email = $("#login-email");
        const password = $("#login-password");
        const error = $("#login-error");
        if (!email.checkValidity() || !email.value.trim() || !password.value) {
          error.hidden = false;
          return;
        }
        error.hidden = true;
        $("#login-screen").remove();
        $(".app-shell").classList.add("is-authenticated");
        const displayName = email.value.split("@")[0].replace(/[._-]+/g, " ").replace(/\\b\\w/g, char => char.toUpperCase()) || "Analyst";
        const welcomeName = $("#welcome-name");
        if (welcomeName) welcomeName.textContent = displayName;
        const profileName = $("#profile-name-side");
        if (profileName) profileName.textContent = displayName;
        const initials = displayName.split(/\\s+/).slice(0,2).map(part => part[0]).join("").toUpperCase();
        $$(".avatar,.top-avatar").forEach(node => { node.textContent = initials || "DA"; });
      });
    }
    if(safeRead(STORE.theme,"dark")==="light")document.body.classList.add("light-theme");
    if(safeRead(STORE.banner,false))$("#dismiss-banner")?.closest(".demo-banner")?.classList.add("hidden");
    const profile=safeRead(STORE.profile,{name:"Demo Analyst",email:""});$("#welcome-name").textContent=(profile.name||"Analyst").split(" ")[0];$("#profile-name-side").textContent=profile.name||"Demo Analyst";
    document.addEventListener("click",e=>{
      const nav=e.target.closest("[data-page]");if(nav){goTo(nav.dataset.page);return;}
      const detail=e.target.closest("[data-scan-detail]");if(detail){scanDetail(detail.dataset.scanDetail);return;}
      const threat=e.target.closest("[data-threat-detail]");if(threat){threatDetail(threat.dataset.threatDetail);return;}
      const read=e.target.closest("[data-alert-read]");if(read){const a=alerts.find(x=>x.id===read.dataset.alertRead);if(a)a.read=!a.read;safeWrite(STORE.alerts,alerts);renderAlerts();renderDashboard();return;}
      const dismiss=e.target.closest("[data-alert-dismiss]");if(dismiss){const a=alerts.find(x=>x.id===dismiss.dataset.alertDismiss);if(a)a.dismissed=true;safeWrite(STORE.alerts,alerts);renderAlerts();renderDashboard();toast("Alert dismissed from this demo inbox.");return;}
      const sample=e.target.closest("[data-sample]");if(sample){$("#url-input").value=sample.dataset.sample;$("#url-input").focus();}
    });
    $("#mobile-menu").addEventListener("click",()=>$("#sidebar").classList.toggle("open"));
    $("#theme-toggle").addEventListener("click",()=>setTheme(!document.body.classList.contains("light-theme")));
    $("#theme-setting").addEventListener("change",e=>setTheme(e.target.checked));
    $("#notifications-setting").addEventListener("change",e=>{safeWrite(STORE.notifications,e.target.checked);toast(e.target.checked?"In-app notifications enabled.":"In-app notifications disabled.");});
    $("#dismiss-banner").addEventListener("click",()=>{safeWrite(STORE.banner,true);$("#dismiss-banner").closest(".demo-banner").classList.add("hidden");});
    $("#scan-form").addEventListener("submit",e=>{e.preventDefault();runScan($("#url-input").value.trim());});
    ["threat-search","threat-severity","threat-type"].forEach(id=>$("#"+id).addEventListener(id==="threat-search"?"input":"change",renderThreats));
    ["alert-search","alert-severity","alert-status"].forEach(id=>$("#"+id).addEventListener(id==="alert-search"?"input":"change",renderAlerts));
    ["history-search","history-level"].forEach(id=>$("#"+id).addEventListener(id==="history-search"?"input":"change",renderHistory));
    $("#mark-all-read").addEventListener("click",()=>{alerts.forEach(a=>{if(!a.dismissed)a.read=true;});safeWrite(STORE.alerts,alerts);renderAlerts();renderDashboard();toast("All visible demo alerts marked as read.");});
    $("#history-body").addEventListener("click",e=>{const btn=e.target.closest("[data-scan-detail]");if(btn)scanDetail(btn.dataset.scanDetail);});
    $("#recent-scans-body").addEventListener("click",e=>{const btn=e.target.closest("[data-scan-detail]");if(btn)scanDetail(btn.dataset.scanDetail);});
    $("#export-history").addEventListener("click",exportCsv);$("#settings-export").addEventListener("click",exportCsv);
    $("#clear-history").addEventListener("click",clearHistory);$("#settings-clear").addEventListener("click",clearHistory);
    $("#reset-demo").addEventListener("click",resetDemo);
    $("#profile-form").addEventListener("submit",e=>{e.preventDefault();const name=$("#profile-name").value.trim();if(!name){toast("Please enter a display name.");return;}safeWrite(STORE.profile,{name,email:$("#profile-email").value.trim()});syncSettings();toast("Profile display preferences saved.");});
    $("#assessment-form").addEventListener("submit",e=>{
      e.preventDefault();const data=new FormData(e.currentTarget);let score=0,issues=[];
      const weights={passwords:{yes:22,no:0,label:"Password reuse"},mfa:{no:18,yes:0,label:"Multi-factor authentication"},links:{no:20,yes:0,label:"Link verification"},updates:{no:15,yes:0,label:"Software updates"},privacy:{yes:15,no:0,label:"Personal information exposure"},downloads:{yes:10,no:0,label:"Untrusted downloads"}};
      for(const [key,config] of Object.entries(weights)){const val=data.get(key);score+=config[val]||0;if((config[val]||0)>0)issues.push(config.label);}
      score=Math.min(100,score);const level=riskLevel(score),box=$("#assessment-result");
      box.innerHTML=`<div class="eyebrow">YOUR EDUCATIONAL RESULT</div><div class="assessment-score">${score}<span style="font-size:14px;color:var(--muted)">/100</span></div><h2>${escapeText(level)} habit-risk indicator</h2><p class="result-note">This score reflects your answers to this checklist only. It is not a professional security audit.</p><hr style="border:0;border-top:1px solid var(--line);margin:18px 0"><h3 style="font-size:11px">Priority areas</h3>${issues.length?`<ul class="assessment-recs">${issues.map(i=>`<li>${escapeText(i)}</li>`).join("")}</ul>`:'<p class="result-note">Great start — no risk-raising answers were selected. Keep reviewing your habits regularly.</p>'}<h3 style="font-size:11px;margin-top:17px">Suggested next steps</h3><ul class="assessment-recs"><li>Enable MFA on critical accounts.</li><li>Use a password manager and unique passwords.</li><li>Verify links and install updates promptly.</li></ul><button class="button button-secondary button-small" id="assessment-to-recs">Explore recommendations →</button>`;
      $("#assessment-to-recs").addEventListener("click",()=>goTo("recommendations"));toast("Your local self-assessment is ready.");
    });
    $("#recommendation-grid").addEventListener("change",e=>{const input=e.target.closest("[data-recommendation]");if(!input)return;let checked=safeRead(STORE.checklist,[]);checked=input.checked?[...new Set([...checked,input.dataset.recommendation])]:checked.filter(id=>id!==input.dataset.recommendation);safeWrite(STORE.checklist,checked);renderRecommendations();});
    $("#dialog-close").addEventListener("click",()=>$("#detail-dialog").close());
    $("#detail-dialog").addEventListener("click",e=>{if(e.target===$("#detail-dialog"))$("#detail-dialog").close();});
    renderDashboard();renderThreats();renderAlerts();renderHistory();renderRecommendations();syncSettings();
  }
  document.addEventListener("DOMContentLoaded",init);
})();