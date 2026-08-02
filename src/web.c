#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "parser.h"

#define DEFAULT_LOGFILE "sample_log/auth.log"
#define DEFAULT_PORT 8080
#define MAX_LINE_LENGTH 1024
#define RESPONSE_HEADER_SIZE 512
#define MAX_REQUEST_SIZE (25 * 1024 * 1024)
#define UPLOAD_LOGFILE "/tmp/ssh_log_analyzer_uploaded_auth.log"
#define LOGFILE_PATH_SIZE 512

typedef enum {
    AUDIT_NONE,
    AUDIT_LOGOUT_ERROR,
    AUDIT_SSH_DISCONNECT_RECEIVED,
    AUDIT_SSH_DISCONNECTED,
    AUDIT_SSH_SESSION_OPENED,
    AUDIT_SSH_SESSION_CLOSED,
    AUDIT_CRON_SESSION_OPENED,
    AUDIT_CRON_SESSION_CLOSED,
    AUDIT_LOGIND_SESSION
} AuditKind;

static const char *html_page =
"<!doctype html>\n"
"<html lang=\"ja\">\n"
"<head>\n"
"<meta charset=\"utf-8\">\n"
"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
"<title>SSH Log Analyzer</title>\n"
"<style>\n"
":root{color-scheme:dark;--bg:#0d1721;--panel:#142333;--panel2:#192b3d;--line:#284156;--text:#edf4fb;--muted:#9fb0c0;--green:#35d07f;--red:#ff4f5f;--amber:#f6b63c;--blue:#4b9bff;--purple:#8c6df2;--cyan:#38d4e8}*{box-sizing:border-box}body{margin:0;background:#0b141d;color:var(--text);font-family:system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}button,input{font:inherit}header{position:sticky;top:0;z-index:5;background:rgba(12,22,32,.94);border-bottom:1px solid var(--line);backdrop-filter:blur(10px)}.top{max-width:1480px;margin:0 auto;padding:16px 18px;display:flex;gap:16px;align-items:center;justify-content:space-between}.title h1{margin:0;font-size:24px;letter-spacing:0}.meta{margin-top:6px;color:var(--muted);font-size:13px;display:flex;gap:14px;flex-wrap:wrap}.actions{display:flex;gap:8px;align-items:center}.seg{display:flex;border:1px solid #49667e;border-radius:7px;overflow:hidden}.seg button,.refresh,.upload button{border:0;color:var(--text);background:#1a2c40;padding:8px 12px;cursor:pointer}.seg button.active{background:#33516c}.refresh,.upload button{border:1px solid #49667e;border-radius:7px}.wrap{max-width:1480px;margin:0 auto;padding:14px 18px 28px}.tabs{display:flex;gap:8px;overflow:auto;padding-bottom:10px}.tab{border:1px solid var(--line);background:#132233;color:var(--muted);padding:9px 12px;border-radius:7px;white-space:nowrap;cursor:pointer}.tab.active{background:#243e58;color:var(--text);border-color:#58738d}.grid{display:grid;gap:12px}.kpis{grid-template-columns:repeat(6,minmax(150px,1fr));margin-bottom:14px}.card{background:linear-gradient(180deg,var(--panel2),var(--panel));border:1px solid var(--line);border-radius:8px;box-shadow:0 12px 30px rgba(0,0,0,.18)}.upload{margin-bottom:12px}.upload form{display:flex;gap:12px;align-items:center;flex-wrap:wrap}.upload h2{margin:0 12px 0 0}.upload input[type=file]{max-width:360px;color:var(--muted)}.upload .hint{color:var(--muted);font-size:13px}.upload .status{color:var(--cyan);font-size:13px}.kpi{padding:16px;text-align:center;min-height:98px}.label{color:var(--muted);font-size:13px;font-weight:700}.value{font-size:30px;font-weight:800;margin-top:6px}.green{color:var(--green)}.red{color:var(--red)}.amber{color:var(--amber)}.blue{color:var(--blue)}.purple{color:var(--purple)}.section{padding:16px}.section h2{font-size:17px;margin:0 0 12px}.dash{grid-template-columns:1.2fr 1fr 1fr}.two{grid-template-columns:1.1fr .9fr}.three{grid-template-columns:repeat(3,1fr)}.bars{display:grid;gap:10px}.bar{display:grid;grid-template-columns:130px 1fr 62px;gap:10px;align-items:center;font-size:13px}.track{height:24px;background:#0e1924;border:1px solid #203548;border-radius:4px;overflow:hidden}.fill{height:100%;min-width:2px}.timeline{height:230px;border-left:1px solid var(--line);border-bottom:1px solid var(--line);position:relative;background:linear-gradient(180deg,rgba(255,255,255,.03),transparent)}.point{position:absolute;width:4px;border-radius:2px;bottom:0}.tablewrap{overflow:auto}table{width:100%;border-collapse:collapse;font-size:13px}th,td{padding:10px;border-bottom:1px solid #24384a;text-align:left;white-space:nowrap}th{color:#c8d7e4;background:#1a2c3d;position:sticky;top:0}tr:hover td{background:#17293a}.pill{display:inline-flex;align-items:center;border-radius:5px;padding:3px 7px;font-size:12px;font-weight:800}.critical{background:#d73743;color:#fff}.high{background:#d95b35;color:#fff}.medium{background:#9f8235;color:#fff}.low{background:#2f8059;color:#fff}.toolbar{display:flex;gap:10px;align-items:center;margin-bottom:12px;flex-wrap:wrap}.search{background:#0e1924;border:1px solid #40586f;color:var(--text);border-radius:7px;padding:9px 11px;min-width:260px}.empty{color:var(--muted);padding:16px;border:1px dashed #40586f;border-radius:8px}.map{height:260px;display:grid;grid-template-columns:repeat(12,1fr);gap:6px;align-content:center}.tile{height:34px;border-radius:5px;background:#22384b;border:1px solid #304e66}.tile.hot1{background:#5a4735}.tile.hot2{background:#9d5338}.tile.hot3{background:#d95743}.tile.hot4{background:#ff4f5f}.footer{color:var(--muted);font-size:12px;margin-top:16px}@media(max-width:1100px){.kpis,.dash,.two,.three{grid-template-columns:1fr 1fr}}@media(max-width:720px){.top{align-items:flex-start;flex-direction:column}.kpis,.dash,.two,.three{grid-template-columns:1fr}.bar{grid-template-columns:95px 1fr 48px}.search{width:100%;min-width:0}.upload form{align-items:stretch;flex-direction:column}.upload input[type=file]{max-width:100%}}\n"
"</style>\n"
"</head>\n"
"<body>\n"
"<header><div class=\"top\"><div class=\"title\"><h1 data-i=\"title\">SSH Log Analyzer Report</h1><div class=\"meta\"><span id=\"generated\"></span><span id=\"source\"></span><span id=\"lineCount\"></span></div></div><div class=\"actions\"><button class=\"refresh\" id=\"reload\" data-i=\"reload\">Reload</button><div class=\"seg\"><button id=\"enBtn\">EN</button><button id=\"jaBtn\" class=\"active\">日本語</button></div></div></div></header>\n"
"<main class=\"wrap\"><nav class=\"tabs\" id=\"tabs\"></nav><section class=\"card section upload\"><form id=\"uploadForm\"><h2 data-i=\"uploadTitle\">Analyze log file</h2><input id=\"logUpload\" type=\"file\" accept=\".log,.txt\"><button type=\"submit\" data-i=\"uploadButton\">Analyze File</button><span class=\"hint\" data-i=\"uploadHint\">Attach an auth.log-format file to analyze it.</span><span class=\"status\" id=\"uploadStatus\"></span></form></section><section class=\"grid kpis\" id=\"kpis\"></section><section id=\"view\"></section><div class=\"footer\" data-i=\"footer\">Generated by ssh-log-analyzer web mode.</div></main>\n"
"<script>\n"
"const I={ja:{title:'SSH Log Analyzer Report',reload:'再読込',footer:'このレポートは ssh-log-analyzer のWebモードで生成されました。',source:'対象ログ',lines:'解析行数',generated:'生成日時',uploadTitle:'ログファイル解析',uploadHint:'auth.log形式のファイルを添付すると、そのファイルを解析します。',uploadButton:'解析する',uploading:'アップロード中...',uploadDone:'解析対象を切り替えました。',uploadFailed:'アップロードに失敗しました。',chooseFile:'ファイルを選択してください。',overview:'概要',failed:'失敗',success:'成功',root:'root',sudo:'sudo',su:'su',audit:'監査',ipSearch:'IP検索',users:'ユーザー',totalSuccess:'総成功回数',totalFailed:'総失敗回数',uniqueIp:'ユニークIP数',uniqueUser:'ユニークユーザー数',rootAttempts:'root試行回数',riskMax:'危険度(最高)',trend:'成功・失敗の推移',topFailedIp:'失敗数 Top 5 IP',topFailedUser:'失敗数 Top 5 ユーザー',alerts:'検出されたアラート',geo:'接続元IPの国・地域分布',ipStats:'IP別 統計サマリ',time:'時刻',type:'種別',ip:'IPアドレス',user:'ユーザー',detail:'詳細',country:'国',region:'地域',failedCount:'失敗',successCount:'成功',rate:'成功率',risk:'危険度',command:'コマンド',loginUser:'実行ユーザー',targetUser:'切替先ユーザー',searchIp:'IPを入力',noRows:'表示できるログはありません。',timeline:'IP別タイムライン',summary:'サマリ',auditInfo:'監査ログ・補助情報'},en:{title:'SSH Log Analyzer Report',reload:'Reload',footer:'Generated by ssh-log-analyzer web mode.',source:'Source log',lines:'Parsed lines',generated:'Generated',uploadTitle:'Analyze Log File',uploadHint:'Attach an auth.log-format file to analyze it.',uploadButton:'Analyze File',uploading:'Uploading...',uploadDone:'Analysis target changed.',uploadFailed:'Upload failed.',chooseFile:'Choose a file first.',overview:'Overview',failed:'Failed',success:'Success',root:'root',sudo:'sudo',su:'su',audit:'Audit',ipSearch:'IP Search',users:'Users',totalSuccess:'Total Success',totalFailed:'Total Failed',uniqueIp:'Unique IPs',uniqueUser:'Unique Users',rootAttempts:'root Attempts',riskMax:'Risk (Max)',trend:'Success / Failure Trend',topFailedIp:'Top 5 Failed IPs',topFailedUser:'Top 5 Failed Users',alerts:'Detected Alerts',geo:'Source IP Country / Region',ipStats:'IP Statistics Summary',time:'Time',type:'Type',ip:'IP Address',user:'User',detail:'Detail',country:'Country',region:'Region',failedCount:'Failed',successCount:'Success',rate:'Success Rate',risk:'Risk',command:'Command',loginUser:'Run User',targetUser:'Target User',searchIp:'Enter IP address',noRows:'No logs to display.',timeline:'IP Timeline',summary:'Summary',auditInfo:'Audit and Supporting Logs'}};\n"
"let lang=localStorage.lang||'ja', data=null, tab='overview'; const tabs=['overview','failed','success','root','sudo','su','audit','ipSearch','users'];\n"
"const $=s=>document.querySelector(s); const esc=v=>String(v==null?'':v).replace(/[&<>\"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[c])); const t=k=>I[lang][k]||k;\n"
"function setLang(v){lang=v;localStorage.lang=v;render()} enBtn.onclick=()=>setLang('en'); jaBtn.onclick=()=>setLang('ja'); reload.onclick=()=>load();\n"
"uploadForm.onsubmit=async e=>{e.preventDefault(); const f=logUpload.files[0]; if(!f){uploadStatus.textContent=t('chooseFile');return} uploadStatus.textContent=t('uploading'); try{const r=await fetch('/api/upload',{method:'POST',headers:{'Content-Type':'text/plain;charset=utf-8','X-File-Name':encodeURIComponent(f.name)},body:f}); if(!r.ok)throw new Error(await r.text()); await load(); tab='overview'; uploadStatus.textContent=t('uploadDone')}catch(err){uploadStatus.textContent=t('uploadFailed')+' '+err.message}};\n"
"async function load(){const r=await fetch('/api/logs?ts='+Date.now());data=await r.json();render()}\n"
"function entries(){return data?.entries||[]} function audits(){return data?.audit||[]}\n"
"function stats(){const e=entries(), ips={}, users={}; let failed=0,success=0,root=0,sudo=0,su=0; e.forEach(x=>{if(x.type==='failed')failed++; if(x.type==='success')success++; if(x.root)root++; if(x.type==='sudo')sudo++; if(x.type==='su')su++; if(x.ip){if(!ips[x.ip])ips[x.ip]={ip:x.ip,country:x.country,region:x.region,failed:0,success:0}; if(x.type==='failed')ips[x.ip].failed++; if(x.type==='success')ips[x.ip].success++} const u=x.user||x.sudo_user||x.su_login_user; if(u){if(!users[u])users[u]={user:u,failed:0,success:0}; if(x.type==='failed')users[u].failed++; if(x.type==='success')users[u].success++}}); return {failed,success,root,sudo,su,ips:Object.values(ips),users:Object.values(users)}}\n"
"function riskFor(ip){const ev=entries().filter(x=>x.ip===ip&&x.type==='failed'); const succ=entries().some(x=>x.ip===ip&&x.type==='success'); const root=ev.some(x=>x.root), invalid=ev.some(x=>x.invalid); const uniq=new Set(ev.map(x=>x.user).filter(Boolean)).size; let best=0; ev.forEach(a=>{let c=ev.filter(b=>b.sec>=a.sec&&b.sec-a.sec<=300).length; if(c>best)best=c}); let score=best>=250?50:best>=100?40:best>=50?30:best>=10?20:0; if(root)score+=20; if(invalid)score+=10; if(uniq>=10)score+=20; if(succ&&ev.length>=10)score+=50; return {score,level:score>=90?'CRITICAL':score>=60?'HIGH':score>=30?'MEDIUM':'LOW'}}\n"
"function render(){if(!data)return; document.documentElement.lang=lang==='ja'?'ja':'en'; document.querySelectorAll('[data-i]').forEach(n=>n.textContent=t(n.dataset.i)); enBtn.classList.toggle('active',lang==='en'); jaBtn.classList.toggle('active',lang==='ja'); $('#generated').textContent=t('generated')+': '+new Date().toLocaleString(); $('#source').textContent=t('source')+': '+data.logfile; $('#lineCount').textContent=t('lines')+': '+data.parsed_lines.toLocaleString(); renderTabs(); renderKpis(); renderView();}\n"
"function renderTabs(){tabsEl=$('#tabs'); tabsEl.innerHTML=tabs.map(x=>`<button class=\"tab ${tab===x?'active':''}\" onclick=\"tab='${x}';renderView();renderTabs()\">${t(x)}</button>`).join('')}\n"
"function renderKpis(){const s=stats(); const max=s.ips.reduce((m,x)=>Math.max(m,riskFor(x.ip).score),0); $('#kpis').innerHTML=[['totalSuccess',s.success,'green'],['totalFailed',s.failed,'red'],['uniqueIp',s.ips.length,'blue'],['uniqueUser',s.users.length,'amber'],['rootAttempts',s.root,'purple'],['riskMax',max>=90?'CRITICAL':max>=60?'HIGH':max>=30?'MEDIUM':'LOW',max>=60?'red':'amber']].map(k=>`<div class=\"card kpi\"><div class=\"label\">${t(k[0])}</div><div class=\"value ${k[2]}\">${k[1].toLocaleString?.()||k[1]}</div></div>`).join('')}\n"
"function bars(rows,key,color){const max=Math.max(1,...rows.map(x=>x[key])); return `<div class=\"bars\">${rows.map(x=>`<div class=\"bar\"><b>${esc(x.ip||x.user)}</b><div class=\"track\"><div class=\"fill\" style=\"width:${Math.max(2,x[key]/max*100)}%;background:${color}\"></div></div><b>${x[key]}</b></div>`).join('')}</div>`}\n"
"function timeline(rows){const max=Math.max(1,...rows.map(x=>x.sec)); return `<div class=\"timeline\">${rows.filter(x=>x.sec>=0).map(x=>`<span class=\"point\" title=\"${esc(x.time+' '+x.type)}\" style=\"left:${x.sec/max*100}%;height:${x.type==='failed'?70:28}%;background:${x.type==='failed'?'var(--red)':'var(--green)'}\"></span>`).join('')}</div>`}\n"
"function table(rows,cols){if(!rows.length)return `<div class=\"empty\">${t('noRows')}</div>`; return `<div class=\"tablewrap\"><table><thead><tr>${cols.map(c=>`<th>${t(c[0])}</th>`).join('')}</tr></thead><tbody>${rows.map(r=>`<tr>${cols.map(c=>`<td>${c[2]?c[2](r):esc(r[c[1]]||'')}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`}\n"
"function eventRows(filter){return entries().filter(filter).map(x=>({...x,detail:x.type==='sudo'?x.command:(x.type==='su'?`${x.su_login_user||''} -> ${x.su_target_user||''}`:(x.method||''))}))}\n"
"function renderView(){const s=stats(), v=$('#view'); const topIp=[...s.ips].sort((a,b)=>b.failed-a.failed).slice(0,5), topUser=[...s.users].sort((a,b)=>b.failed-a.failed).slice(0,5); if(tab==='overview'){v.innerHTML=`<div class=\"grid dash\"><div class=\"card section\"><h2>${t('trend')}</h2>${timeline(entries().filter(x=>x.type==='failed'||x.type==='success'))}</div><div class=\"card section\"><h2>${t('topFailedIp')}</h2>${bars(topIp,'failed','var(--red)')}</div><div class=\"card section\"><h2>${t('topFailedUser')}</h2>${bars(topUser,'failed','var(--purple)')}</div></div><div class=\"grid two\" style=\"margin-top:12px\"><div class=\"card section\"><h2>${t('ipStats')}</h2>${ipTable(s.ips)}</div><div class=\"card section\"><h2>${t('geo')}</h2>${geoMap(s.ips)}</div></div>`; return} if(tab==='failed')return listEvents(x=>x.type==='failed'); if(tab==='success')return listEvents(x=>x.type==='success'); if(tab==='root')return listEvents(x=>x.root); if(tab==='sudo')return listEvents(x=>x.type==='sudo'); if(tab==='su')return listEvents(x=>x.type==='su'); if(tab==='audit')return auditView(); if(tab==='ipSearch')return ipSearch(); if(tab==='users')return userView(s.users)}\n"
"function listEvents(filter){const rows=eventRows(filter); $('#view').innerHTML=`<div class=\"card section\"><h2>${t(tab)}</h2>${table(rows,[['time','time'],['type','type'],['ip','ip'],['user','user'],['country','country'],['region','region'],['detail','detail']])}</div>`}\n"
"function ipTable(ips){return table([...ips].sort((a,b)=>(b.failed+b.success)-(a.failed+a.success)),[['ip','ip'],['country','country'],['region','region'],['successCount','success'],['failedCount','failed'],['rate','',r=>{const total=r.success+r.failed; return total?((r.success/total)*100).toFixed(2)+'%':'0%'}],['risk','',r=>{const z=riskFor(r.ip); return `<span class=\"pill ${z.level.toLowerCase()}\">${z.score} ${z.level}</span>`}]])}\n"
"function geoMap(ips){const hot={}; ips.forEach(x=>{const k=x.country||x.region||'unknown'; hot[k]=(hot[k]||0)+x.failed+x.success}); const vals=Object.values(hot), max=Math.max(1,...vals); return `<div class=\"map\">${Array.from({length:48}).map((_,i)=>{const v=vals[i%Math.max(1,vals.length)]||0; const h=v/max>.75?4:v/max>.5?3:v/max>.25?2:v?1:0; return `<div class=\"tile hot${h}\"></div>`}).join('')}</div><div class=\"tablewrap\"><table><tbody>${Object.entries(hot).sort((a,b)=>b[1]-a[1]).map(x=>`<tr><td>${esc(x[0])}</td><td>${x[1]}</td></tr>`).join('')}</tbody></table></div>`}\n"
"function auditView(){const rows=audits(); $('#view').innerHTML=`<div class=\"card section\"><h2>${t('auditInfo')}</h2>${table(rows,[['time','time'],['type','kind'],['user','user'],['ip','ip'],['detail','detail']])}</div>`}\n"
"function ipSearch(){const current=sessionStorage.ipq||''; const rows=eventRows(x=>!current||x.ip===current); $('#view').innerHTML=`<div class=\"card section\"><div class=\"toolbar\"><h2>${t('timeline')}</h2><input class=\"search\" id=\"ipq\" placeholder=\"${t('searchIp')}\" value=\"${esc(current)}\"></div>${current?`<div class=\"grid two\"><div>${table(rows,[['time','time'],['type','type'],['user','user'],['detail','detail']])}</div><div>${timeline(rows)}</div></div>`:`<div class=\"empty\">${t('searchIp')}</div>`}</div>`; const input=$('#ipq'); input.oninput=()=>{sessionStorage.ipq=input.value.trim(); ipSearch()}}\n"
"function userView(users){$('#view').innerHTML=`<div class=\"card section\"><h2>${t('users')}</h2>${table([...users].sort((a,b)=>(b.failed+b.success)-(a.failed+a.success)),[['user','user'],['successCount','success'],['failedCount','failed'],['rate','',r=>{const total=r.success+r.failed; return total?((r.success/total)*100).toFixed(2)+'%':'0%'}]])}</div>`}\n"
"load().catch(e=>{$('#view').innerHTML='<div class=\"empty\">'+esc(e.message)+'</div>'});\n"
"</script>\n"
"</body>\n"
"</html>\n";

static volatile sig_atomic_t should_stop = 0;

static void handle_signal(int signal_number) {
    (void)signal_number;
    should_stop = 1;
}

static AuditKind audit_kind(const char *line) {
    if (strstr(line, "syslogin_perform_logout") != NULL) return AUDIT_LOGOUT_ERROR;
    if (strstr(line, "Received disconnect") != NULL) return AUDIT_SSH_DISCONNECT_RECEIVED;
    if (strstr(line, "Disconnected from user") != NULL) return AUDIT_SSH_DISCONNECTED;
    if (strstr(line, "pam_unix(sshd:session): session opened") != NULL) return AUDIT_SSH_SESSION_OPENED;
    if (strstr(line, "pam_unix(sshd:session): session closed") != NULL) return AUDIT_SSH_SESSION_CLOSED;
    if (strstr(line, "pam_unix(cron:session): session opened") != NULL) return AUDIT_CRON_SESSION_OPENED;
    if (strstr(line, "pam_unix(cron:session): session closed") != NULL) return AUDIT_CRON_SESSION_CLOSED;
    if (strstr(line, "systemd-logind") != NULL &&
        (strstr(line, "New session") != NULL || strstr(line, "logged out") != NULL || strstr(line, "Removed session") != NULL)) {
        return AUDIT_LOGIND_SESSION;
    }
    return AUDIT_NONE;
}

static const char *audit_label(AuditKind kind) {
    switch (kind) {
        case AUDIT_LOGOUT_ERROR: return "logout error";
        case AUDIT_SSH_DISCONNECT_RECEIVED: return "ssh disconnect received";
        case AUDIT_SSH_DISCONNECTED: return "ssh disconnected";
        case AUDIT_SSH_SESSION_OPENED: return "ssh session opened";
        case AUDIT_SSH_SESSION_CLOSED: return "ssh session closed";
        case AUDIT_CRON_SESSION_OPENED: return "cron session opened";
        case AUDIT_CRON_SESSION_CLOSED: return "cron session closed";
        case AUDIT_LOGIND_SESSION: return "logind session";
        case AUDIT_NONE:
        default: return "unknown";
    }
}

static void json_string(FILE *out, const char *value) {
    const unsigned char *p = (const unsigned char *)value;
    fputc('"', out);
    while (*p != '\0') {
        if (*p == '"' || *p == '\\') {
            fputc('\\', out);
            fputc(*p, out);
        } else if (*p == '\n') {
            fputs("\\n", out);
        } else if (*p == '\r') {
            fputs("\\r", out);
        } else if (*p == '\t') {
            fputs("\\t", out);
        } else if (*p < 32) {
            fprintf(out, "\\u%04x", *p);
        } else {
            fputc(*p, out);
        }
        p++;
    }
    fputc('"', out);
}

static const char *entry_type(const LogEntry *entry) {
    if (entry->is_sudo) return "sudo";
    if (entry->is_su) return "su";
    if (entry->is_success) return "success";
    if (entry->is_failed) return "failed";
    return "other";
}

static void audit_field_after(const char *line, const char *marker, char *dest, size_t dest_size) {
    const char *start = strstr(line, marker);
    (void)dest_size;
    if (start == NULL || sscanf(start + strlen(marker), "%63s", dest) != 1) {
        dest[0] = '\0';
    }
}

static void write_audit_object(FILE *out, const char *line, AuditKind kind, int *first) {
    char time_text[MAX_TIME_LENGTH] = "";
    char user[MAX_USER_LENGTH] = "";
    char ip[MAX_IP_LENGTH] = "";
    int year, iso_month, iso_day, hour, minute, second, day;
    char month[4];

    if (sscanf(line, "%d-%d-%dT%d:%d:%d", &year, &iso_month, &iso_day, &hour, &minute, &second) == 6) {
        (void)year;
        (void)iso_month;
        (void)iso_day;
        snprintf(time_text, sizeof(time_text), "%02d:%02d:%02d", hour, minute, second);
    } else if (sscanf(line, "%3s %d %d:%d:%d", month, &day, &hour, &minute, &second) == 5) {
        snprintf(time_text, sizeof(time_text), "%02d:%02d:%02d", hour, minute, second);
    }
    if (kind == AUDIT_SSH_DISCONNECTED) {
        const char *start = strstr(line, "Disconnected from user ");
        if (start != NULL) {
            sscanf(start + strlen("Disconnected from user "), "%63s %63s", user, ip);
        }
    } else if (kind == AUDIT_SSH_DISCONNECT_RECEIVED) {
        const char *start = strstr(line, "Received disconnect from ");
        if (start != NULL) {
            sscanf(start + strlen("Received disconnect from "), "%63s", ip);
        }
    } else {
        audit_field_after(line, "user ", user, sizeof(user));
    }

    if (!*first) fputc(',', out);
    *first = 0;
    fputs("{\"time\":", out); json_string(out, time_text);
    fputs(",\"kind\":", out); json_string(out, audit_label(kind));
    fputs(",\"user\":", out); json_string(out, user);
    fputs(",\"ip\":", out); json_string(out, ip);
    fputs(",\"detail\":", out); json_string(out, line);
    fputc('}', out);
}

static int write_json_report(FILE *out, const char *logfile) {
    FILE *fp = fopen(logfile, "r");
    char line[MAX_LINE_LENGTH];
    LogEntry entry;
    unsigned long total_lines = 0;
    unsigned long parsed_lines = 0;
    int first_entry = 1;
    int first_audit = 1;

    if (fp == NULL) {
        return 0;
    }

    fputs("{\"logfile\":", out); json_string(out, logfile);
    fputs(",\"entries\":[", out);
    while (fgets(line, sizeof(line), fp) != NULL) {
        total_lines++;
        if (!parse_log_line(line, &entry)) {
            continue;
        }
        parsed_lines++;
        if (!first_entry) fputc(',', out);
        first_entry = 0;
        fputs("{\"time\":", out); json_string(out, entry.time_text);
        fprintf(out, ",\"sec\":%d", entry.has_timestamp ? entry.timestamp_seconds : -1);
        fputs(",\"type\":", out); json_string(out, entry_type(&entry));
        fprintf(out, ",\"root\":%s,\"invalid\":%s", entry.is_root ? "true" : "false", entry.is_invalid_user ? "true" : "false");
        fputs(",\"ip\":", out); json_string(out, entry.ip);
        fputs(",\"country\":", out); json_string(out, entry.country);
        fputs(",\"region\":", out); json_string(out, entry.region);
        fputs(",\"user\":", out); json_string(out, entry.user);
        fputs(",\"method\":", out); json_string(out, entry.auth_method);
        fputs(",\"sudo_user\":", out); json_string(out, entry.sudo_user);
        fputs(",\"sudo_target_user\":", out); json_string(out, entry.sudo_target_user);
        fputs(",\"command\":", out); json_string(out, entry.command);
        fputs(",\"su_login_user\":", out); json_string(out, entry.su_login_user);
        fputs(",\"su_target_user\":", out); json_string(out, entry.su_target_user);
        fputc('}', out);
    }
    fputs("],\"audit\":[", out);
    rewind(fp);
    while (fgets(line, sizeof(line), fp) != NULL) {
        AuditKind kind = audit_kind(line);
        if (kind != AUDIT_NONE) {
            write_audit_object(out, line, kind, &first_audit);
        }
    }
    fprintf(out, "],\"total_lines\":%lu,\"parsed_lines\":%lu}", total_lines, parsed_lines);
    fclose(fp);
    return 1;
}

static void send_response(int client_fd, const char *status, const char *content_type, const char *body) {
    char header[RESPONSE_HEADER_SIZE];
    size_t body_len = strlen(body);
    int header_len = snprintf(header, sizeof(header),
                              "HTTP/1.1 %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
                              status, content_type, body_len);
    (void)send(client_fd, header, (size_t)header_len, 0);
    (void)send(client_fd, body, body_len, 0);
}

static void send_file_response(int client_fd, const char *status, const char *content_type, FILE *body) {
    char header[RESPONSE_HEADER_SIZE];
    long body_len;
    int header_len;

    fflush(body);
    body_len = ftell(body);
    if (body_len < 0) {
        send_response(client_fd, "500 Internal Server Error", "text/plain; charset=utf-8", "Failed to build response");
        return;
    }
    rewind(body);
    header_len = snprintf(header, sizeof(header),
                          "HTTP/1.1 %s\r\nContent-Type: %s\r\nContent-Length: %ld\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n",
                          status, content_type, body_len);
    (void)send(client_fd, header, (size_t)header_len, 0);
    while (!feof(body)) {
        char buffer[4096];
        size_t read_len = fread(buffer, 1, sizeof(buffer), body);
        if (read_len > 0) {
            (void)send(client_fd, buffer, read_len, 0);
        }
    }
}

static char *find_header_end(char *buffer, size_t length) {
    size_t i;

    for (i = 0; i + 3 < length; i++) {
        if (buffer[i] == '\r' && buffer[i + 1] == '\n' &&
            buffer[i + 2] == '\r' && buffer[i + 3] == '\n') {
            return buffer + i + 4;
        }
    }

    return NULL;
}

static long request_content_length(const char *request) {
    const char *header = strstr(request, "Content-Length:");
    char *endptr;
    long length;

    if (header == NULL) {
        return 0;
    }

    header += strlen("Content-Length:");
    while (*header == ' ') {
        header++;
    }

    length = strtol(header, &endptr, 10);
    if (endptr == header || length < 0) {
        return -1;
    }

    return length;
}

static char *read_http_request(int client_fd, size_t *request_length, char **body, size_t *body_length) {
    size_t capacity = 8192;
    size_t used = 0;
    char *buffer = malloc(capacity + 1);
    char *body_start = NULL;
    long content_length = 0;

    if (buffer == NULL) {
        return NULL;
    }

    while (1) {
        ssize_t read_len;
        if (used == capacity) {
            char *new_buffer;
            if (capacity >= MAX_REQUEST_SIZE) {
                free(buffer);
                return NULL;
            }
            capacity *= 2;
            if (capacity > MAX_REQUEST_SIZE) {
                capacity = MAX_REQUEST_SIZE;
            }
            new_buffer = realloc(buffer, capacity + 1);
            if (new_buffer == NULL) {
                free(buffer);
                return NULL;
            }
            buffer = new_buffer;
        }

        read_len = recv(client_fd, buffer + used, capacity - used, 0);
        if (read_len <= 0) {
            free(buffer);
            return NULL;
        }
        used += (size_t)read_len;
        buffer[used] = '\0';

        body_start = find_header_end(buffer, used);
        if (body_start == NULL) {
            continue;
        }

        content_length = request_content_length(buffer);
        if (content_length < 0 || content_length > MAX_REQUEST_SIZE) {
            free(buffer);
            return NULL;
        }

        if ((size_t)(body_start - buffer) + (size_t)content_length <= used) {
            break;
        }
    }

    *request_length = used;
    *body = body_start;
    *body_length = (size_t)content_length;
    return buffer;
}

static void handle_upload(int client_fd,
                          const char *body,
                          size_t body_length,
                          char *current_logfile,
                          size_t current_logfile_size) {
    FILE *fp;
    char response[256];

    if (body_length == 0) {
        send_response(client_fd, "400 Bad Request", "application/json; charset=utf-8", "{\"error\":\"empty upload\"}");
        return;
    }

    fp = fopen(UPLOAD_LOGFILE, "wb");
    if (fp == NULL) {
        send_response(client_fd, "500 Internal Server Error", "application/json; charset=utf-8", "{\"error\":\"failed to save uploaded file\"}");
        return;
    }

    if (fwrite(body, 1, body_length, fp) != body_length) {
        fclose(fp);
        send_response(client_fd, "500 Internal Server Error", "application/json; charset=utf-8", "{\"error\":\"failed to write uploaded file\"}");
        return;
    }
    fclose(fp);

    snprintf(current_logfile, current_logfile_size, "%s", UPLOAD_LOGFILE);

    snprintf(response, sizeof(response),
             "{\"ok\":true,\"logfile\":\"%s\",\"bytes\":%zu}",
             UPLOAD_LOGFILE,
             body_length);
    send_response(client_fd, "200 OK", "application/json; charset=utf-8", response);
}

static void handle_client(int client_fd, char *current_logfile, size_t current_logfile_size) {
    char *request;
    char *body;
    size_t request_length;
    size_t body_length;
    FILE *tmp;

    request = read_http_request(client_fd, &request_length, &body, &body_length);
    (void)request_length;
    if (request == NULL) {
        send_response(client_fd, "413 Payload Too Large", "application/json; charset=utf-8", "{\"error\":\"invalid or too large request\"}");
        return;
    }

    if (strncmp(request, "GET /api/logs", 13) == 0) {
        tmp = tmpfile();
        if (tmp == NULL || !write_json_report(tmp, current_logfile)) {
            if (tmp != NULL) fclose(tmp);
            send_response(client_fd, "500 Internal Server Error", "application/json; charset=utf-8", "{\"error\":\"failed to read log file\"}");
            free(request);
            return;
        }
        send_file_response(client_fd, "200 OK", "application/json; charset=utf-8", tmp);
        fclose(tmp);
        free(request);
        return;
    }

    if (strncmp(request, "POST /api/upload", 16) == 0) {
        handle_upload(client_fd, body, body_length, current_logfile, current_logfile_size);
        free(request);
        return;
    }

    if (strncmp(request, "GET / ", 6) == 0 || strncmp(request, "GET /index.html", 15) == 0) {
        send_response(client_fd, "200 OK", "text/html; charset=utf-8", html_page);
        free(request);
        return;
    }

    send_response(client_fd, "404 Not Found", "text/plain; charset=utf-8", "Not Found");
    free(request);
}

int main(int argc, char *argv[]) {
    char current_logfile[LOGFILE_PATH_SIZE];
    int port = argc > 2 ? atoi(argv[2]) : DEFAULT_PORT;
    int server_fd;
    struct sockaddr_in address;
    int opt = 1;

    snprintf(current_logfile, sizeof(current_logfile), "%s", argc > 1 ? argv[1] : DEFAULT_LOGFILE);

    if (port <= 0 || port > 65535) {
        fprintf(stderr, "Invalid port: %d\n", port);
        return 1;
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGPIPE, SIG_IGN);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons((uint16_t)port);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind");
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 16) < 0) {
        perror("listen");
        close(server_fd);
        return 1;
    }

    printf("SSH Log Analyzer web UI\n");
    printf("Log file: %s\n", current_logfile);
    printf("Open: http://localhost:%d\n", port);
    printf("Press Ctrl+C to stop.\n");
    fflush(stdout);

    while (!should_stop) {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            break;
        }
        handle_client(client_fd, current_logfile, sizeof(current_logfile));
        close(client_fd);
    }

    close(server_fd);
    return 0;
}
