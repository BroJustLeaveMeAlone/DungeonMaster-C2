import { useState } from 'react'
import { X } from 'lucide-react'

// ── Schema ────────────────────────────────────────────────────────────────────

type ArgDef = {
  key:         string
  label:       string
  type:        'text' | 'number' | 'textarea' | 'select'
  required?:   boolean
  placeholder?: string
  options?:    string[]
  default?:    string
}

type MethodDef = {
  method: string
  label:  string
  desc:   string
  args:   ArgDef[]
}

type CategoryDef = {
  type:    string
  label:   string
  color:   string
  methods: MethodDef[]
}

const SCHEMA: CategoryDef[] = [
  {
    type: 'enum', label: 'Enumeration', color: '#4090ff',
    methods: [
      { method: 'computer',            label: 'Computer Info',          desc: 'Full system fingerprint (OS, patches, AV, env)', args: [] },
      { method: 'processes',           label: 'Process List',           desc: 'ToolHelp32 snapshot', args: [] },
      { method: 'services',            label: 'Services',               desc: 'Service list via SCM', args: [] },
      { method: 'tasks',               label: 'Scheduled Tasks',        desc: 'Filesystem walk of task XML', args: [] },
      { method: 'sessions',            label: 'Active Sessions',        desc: 'NetSessionEnum', args: [] },
      { method: 'shares',              label: 'Shares',                 desc: 'NetShareEnum', args: [] },
      { method: 'users',               label: 'Local Users',            desc: 'NetUserEnum', args: [] },
      { method: 'groups',              label: 'Local Groups',           desc: 'NetLocalGroupEnum', args: [] },
      { method: 'localadmins',         label: 'Local Admins',           desc: 'Members of Administrators group', args: [] },
      { method: 'domain',              label: 'Domain Info',            desc: 'Domain trusts + workstation config', args: [] },
      { method: 'routes',              label: 'Routing Table',          desc: 'GetIpForwardTable2', args: [] },
      { method: 'netdiscovery',        label: 'Network Discovery',      desc: 'TCP port scan / host discovery', args: [
        { key: 'target',      label: 'Target (CIDR or host)', type: 'text',   required: true, placeholder: '192.168.1.0/24' },
        { key: 'ports',       label: 'Ports',                 type: 'text',   placeholder: '22,80,443,445,3389' },
        { key: 'timeout_ms',  label: 'Timeout (ms)',          type: 'number', placeholder: '500' },
      ]},
      { method: 'bloodhound',          label: 'BloodHound Collection',  desc: 'AD enumeration for BloodHound', args: [] },
      { method: 'acl',                 label: 'ACL Enumeration',        desc: 'AD object ACL enumeration', args: [] },
      { method: 'unconstrained-deleg', label: 'Unconstrained Delegation', desc: 'Find computers with unconstrained delegation', args: [] },
    ],
  },
  {
    type: 'collect', label: 'Collection', color: '#00d4b0',
    methods: [
      { method: 'clipboard',      label: 'Clipboard',           desc: 'Read clipboard contents', args: [] },
      { method: 'screen-record',  label: 'Screenshot',          desc: 'Take N screenshots via GDI', args: [
        { key: 'count',       label: 'Frame count',  type: 'number', default: '1' },
        { key: 'interval_ms', label: 'Interval (ms)', type: 'number', placeholder: '1000' },
      ]},
      { method: 'keylog-start',   label: 'Keylog Start',        desc: 'Start keystroke capture (GetAsyncKeyState)', args: [] },
      { method: 'keylog-dump',    label: 'Keylog Dump',         desc: 'Flush captured keystrokes', args: [] },
      { method: 'keylog-stop',    label: 'Keylog Stop',         desc: 'Stop keystroke capture', args: [] },
      { method: 'vault',          label: 'Credential Vault',    desc: 'CredEnumerateW (Windows Credential Manager)', args: [] },
      { method: 'browser-creds',  label: 'Browser Credentials', desc: 'Chrome/Edge Login Data + AES-GCM decrypt', args: [] },
      { method: 'browser-history',label: 'Browser History',     desc: 'Chrome/Edge SQLite History', args: [] },
      { method: 'wifi',           label: 'WiFi Passwords',      desc: 'WlanGetProfile for all profiles', args: [] },
      { method: 'ssh-keys',       label: 'SSH Keys',            desc: 'Harvest ~/.ssh/ and PuTTY registry', args: [] },
      { method: 'certs',          label: 'Certificates',        desc: 'Export PFX from certificate stores', args: [] },
      { method: 'email',          label: 'Email (MAPI)',         desc: 'Outlook inbox via MAPI/Outlook', args: [
        { key: 'count', label: 'Message count', type: 'number', placeholder: '50' },
      ]},
      { method: 'dpapi',          label: 'DPAPI Decrypt',       desc: 'CryptUnprotectData on supplied blob', args: [
        { key: 'blob', label: 'Encrypted blob (hex or base64)', type: 'textarea', required: true },
      ]},
      { method: 'file-search',    label: 'File Search',         desc: 'Recursive glob + optional content grep', args: [
        { key: 'path', label: 'Root path', type: 'text',   required: true, placeholder: 'C:\\Users' },
        { key: 'ext',  label: 'Extensions', type: 'text',  placeholder: '.docx,.pdf,.xlsx' },
        { key: 'grep', label: 'Content grep (regex)', type: 'text', placeholder: 'password' },
      ]},
    ],
  },
  {
    type: 'cred', label: 'Credentials', color: '#ff3a4c',
    methods: [
      { method: 'lsass',          label: 'LSASS (MiniDump)',     desc: 'MiniDumpWriteDump via handle duplication', args: [] },
      { method: 'lsass-pss',      label: 'LSASS (PSS)',          desc: 'PssCaptureSnapshot — quieter variant', args: [] },
      { method: 'lsass-syscall',  label: 'LSASS (Syscall)',      desc: 'Direct syscalls, bypasses userland hooks', args: [] },
      { method: 'kerberoast',     label: 'Kerberoasting',        desc: 'Request TGS for SPN accounts, return crackable hashes', args: [
        { key: 'spn', label: 'Specific SPN (optional)', type: 'text', placeholder: 'leave blank for all' },
      ]},
      { method: 'asrep-roast',    label: 'ASREP Roasting',       desc: 'Request AS-REP for no-preauth accounts', args: [
        { key: 'user', label: 'Specific user (optional)', type: 'text' },
      ]},
      { method: 'pth',            label: 'Pass the Hash',        desc: 'Spawn process with NTLM hash', args: [
        { key: 'user', label: 'Username',          type: 'text',     required: true },
        { key: 'hash', label: 'NTLM hash (LM:NT)', type: 'text',     required: true },
        { key: 'cmd',  label: 'Command to spawn',  type: 'text',     placeholder: 'cmd.exe' },
      ]},
      { method: 'ptt',            label: 'Pass the Ticket',      desc: 'Inject Kerberos ticket into current session', args: [
        { key: 'ticket_b64', label: 'Base64 ticket (.kirbi)', type: 'textarea', required: true },
        { key: 'purge',      label: 'Purge existing tickets first', type: 'select', options: ['false','true'], default: 'false' },
      ]},
      { method: 'opth',           label: 'Overpass the Hash',    desc: 'Convert NTLM hash → Kerberos TGT and inject into session', args: [
        { key: 'user',        label: 'Username',                   type: 'text', required: true },
        { key: 'ntlm',        label: 'NTLM hash (32-char hex)',    type: 'text', required: true },
        { key: 'domain',      label: 'Domain (FQDN)',              type: 'text', required: true },
        { key: 'dc',          label: 'DC hostname/IP (optional)',   type: 'text', placeholder: '10.10.10.2' },
        { key: 'aes256_key',  label: 'AES-256 key (64-char hex, optional)', type: 'text', placeholder: 'for WS2022 w/ RC4 disabled' },
        { key: 'cmd',         label: 'Run after inject (optional)', type: 'text', placeholder: 'dir \\\\DC01\\C$' },
      ]},
      { method: 'dcsync',         label: 'DCSync',               desc: 'Replicate credentials from DC via DRSUAPI', args: [
        { key: 'user',   label: 'Target user (blank = all)', type: 'text', placeholder: 'krbtgt' },
        { key: 'domain', label: 'Domain', type: 'text', placeholder: 'AMITLAB.local' },
      ]},
      { method: 'golden-ticket',  label: 'Golden Ticket',        desc: 'Forge TGT with krbtgt hash', args: [
        { key: 'user',         label: 'Username to forge', type: 'text', required: true, placeholder: 'Administrator' },
        { key: 'domain',       label: 'Domain',            type: 'text', required: true },
        { key: 'sid',          label: 'Domain SID',        type: 'text', required: true },
        { key: 'krbtgt_hash',  label: 'krbtgt NTLM hash', type: 'text', required: true },
      ]},
      { method: 'silver-ticket',  label: 'Silver Ticket',        desc: 'Forge TGS for specific service', args: [
        { key: 'user',         label: 'Username to forge', type: 'text', required: true },
        { key: 'domain',       label: 'Domain',            type: 'text', required: true },
        { key: 'sid',          label: 'Domain SID',        type: 'text', required: true },
        { key: 'service_hash', label: 'Service NTLM hash', type: 'text', required: true },
        { key: 'spn',          label: 'Target SPN',        type: 'text', required: true },
      ]},
      { method: 'diamond-ticket', label: 'Diamond Ticket',       desc: 'Modify existing TGT (stealthier than golden)', args: [
        { key: 'user',        label: 'Username',     type: 'text', required: true },
        { key: 'domain',      label: 'Domain',       type: 'text', required: true },
        { key: 'krbtgt_hash', label: 'krbtgt hash',  type: 'text', required: true },
      ]},
    ],
  },
  {
    type: 'priv', label: 'Privilege Esc.', color: '#ff7830',
    methods: [
      { method: 'uac-fodhelper',       label: 'UAC — fodhelper',         desc: 'UAC bypass via ms-settings registry hijack', args: [
        { key: 'cmd', label: 'Command to run elevated', type: 'text', required: true, placeholder: 'C:\\Windows\\Temp\\agent.exe' },
      ]},
      { method: 'uac-eventvwr',        label: 'UAC — eventvwr',          desc: 'UAC bypass via mscfile registry hijack', args: [
        { key: 'cmd', label: 'Command to run elevated', type: 'text', required: true },
      ]},
      { method: 'uac-sdclt',           label: 'UAC — sdclt',             desc: 'UAC bypass via App Paths control.exe hijack', args: [
        { key: 'cmd', label: 'Command to run elevated', type: 'text', required: true },
      ]},
      { method: 'token-steal',         label: 'Token Steal',             desc: 'Steal SYSTEM token from winlogon, impersonate or spawn', args: [
        { key: 'pid', label: 'Target PID (optional, auto = winlogon)', type: 'number' },
      ]},
      { method: 'token-make',          label: 'Token Make',              desc: 'LogonUser → impersonate with creds', args: [
        { key: 'user',   label: 'Username',  type: 'text', required: true, placeholder: 'AMITLAB\\Administrator' },
        { key: 'pass',   label: 'Password',  type: 'text', required: true },
        { key: 'domain', label: 'Domain',    type: 'text', placeholder: 'AMITLAB' },
      ]},
      { method: 'sam-dump',            label: 'SAM Dump',                desc: 'Hive extraction → offline NTLM hashes (SeBackupPrivilege)', args: [] },
      { method: 'potato',              label: 'Potato Escalation',       desc: 'SeImpersonatePrivilege → SYSTEM (PrintSpooler)', args: [] },
      { method: 'pipe-impersonate',    label: 'Pipe Impersonation',      desc: 'Named pipe server, wait for privileged client', args: [
        { key: 'timeout_ms', label: 'Timeout (ms)', type: 'number', placeholder: '15000' },
      ]},
      { method: 'shadow-creds',        label: 'Shadow Credentials',      desc: 'Write msDS-KeyCredentialLink → PKINIT auth', args: [
        { key: 'target', label: 'Target DN or samAccountName', type: 'text', required: true },
      ]},
      { method: 'adcs',                label: 'ADCS ESC Abuse',          desc: 'Request cert via vulnerable template', args: [
        { key: 'template', label: 'Template name', type: 'text', required: true, placeholder: 'VulnTemplate-ESC1' },
        { key: 'san',      label: 'Subject Alt Name (SAN)', type: 'text', placeholder: 'Administrator@amitlab.local' },
        { key: 'ca',       label: 'CA name', type: 'text', placeholder: 'DC01\\AMITLAB-CA' },
      ]},
      { method: 's4u',                 label: 'S4U2Self / S4U2Proxy',    desc: 'Constrained delegation abuse', args: [
        { key: 'user', label: 'User to impersonate', type: 'text', required: true },
        { key: 'spn',  label: 'Target SPN',          type: 'text', required: true },
      ]},
      { method: 'rbcd',                label: 'RBCD Abuse',              desc: 'Resource-Based Constrained Delegation', args: [
        { key: 'target',           label: 'Target computer', type: 'text', required: true },
        { key: 'attacker_computer', label: 'Attacker computer', type: 'text', required: true },
      ]},
      { method: 'acl-abuse',           label: 'ACL Abuse',               desc: 'Targeted ACE write (GenericWrite, WriteDACL, etc.)', args: [
        { key: 'target', label: 'Target DN or samAccountName', type: 'text', required: true },
        { key: 'right',  label: 'Right', type: 'select', required: true,
          options: ['GenericWrite', 'WriteDACL', 'WriteOwner', 'ForceChangePassword', 'GenericAll'] },
        { key: 'value',  label: 'Value (attribute writes)', type: 'text' },
      ]},
      { method: 'unquoted-paths',      label: 'Unquoted Service Paths',  desc: 'Enumerate unquoted service binary paths', args: [] },
      { method: 'dll-hijack',          label: 'DLL Hijack Targets',      desc: 'Writable PATH dirs + known DLL hijack targets', args: [] },
      { method: 'always-install-elevated', label: 'AlwaysInstallElevated', desc: 'Check AIE registry flags', args: [] },
    ],
  },
  {
    type: 'persist', label: 'Persistence', color: '#9966ff',
    methods: [
      { method: 'reg',     label: 'Registry Run Key',  desc: 'Write HKCU/HKLM Run key', args: [
        { key: 'key',  label: 'Registry path', type: 'text', required: true, placeholder: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' },
        { key: 'val',  label: 'Value name',    type: 'text', required: true, placeholder: 'Updater' },
        { key: 'data', label: 'Payload path',  type: 'text', required: true, placeholder: 'C:\\Users\\Public\\agent.exe' },
      ]},
      { method: 'reg-rm',  label: 'Remove Run Key',    desc: 'Delete a Run registry value', args: [
        { key: 'key', label: 'Registry path', type: 'text', required: true },
        { key: 'val', label: 'Value name',    type: 'text', required: true },
      ]},
      { method: 'task',    label: 'Scheduled Task',    desc: 'Create scheduled task via schtasks (needs elevation)', args: [
        { key: 'name',    label: 'Task name',     type: 'text',   required: true, placeholder: 'WindowsUpdate' },
        { key: 'cmd',     label: 'Command',       type: 'text',   required: true },
        { key: 'trigger', label: 'Trigger',       type: 'select', options: ['ONLOGON','ONSTART','DAILY'], default: 'ONLOGON' },
      ]},
      { method: 'svc',     label: 'Service',           desc: 'Create + start Windows service (needs elevation)', args: [
        { key: 'name',    label: 'Service name',   type: 'text', required: true, placeholder: 'WinAgent' },
        { key: 'bin',     label: 'Binary path',    type: 'text', required: true },
        { key: 'display', label: 'Display name',   type: 'text', placeholder: 'Windows Agent Service' },
      ]},
      { method: 'svc-rm',  label: 'Remove Service',    desc: 'Delete service via SCM', args: [
        { key: 'name', label: 'Service name', type: 'text', required: true },
      ]},
      { method: 'startup', label: 'Startup Folder',    desc: 'Copy payload to Startup folder', args: [
        { key: 'src',  label: 'Source path',            type: 'text', required: true },
        { key: 'name', label: 'Destination filename',   type: 'text', placeholder: 'update.exe' },
      ]},
      { method: 'com',     label: 'COM Hijack',         desc: 'HKCU COM CLSID hijack (InprocServer32)', args: [
        { key: 'clsid', label: 'CLSID',    type: 'text', required: true, placeholder: '{BCDE0395-E52F-467C-8E3D-C4579291692E}' },
        { key: 'dll',   label: 'DLL path', type: 'text', required: true },
      ]},
      { method: 'wmi',     label: 'WMI Subscription',  desc: 'WMI event filter + CommandLine consumer via mofcomp', args: [
        { key: 'name', label: 'Subscription name', type: 'text', required: true, placeholder: 'WinMgmt' },
        { key: 'cmd',  label: 'Command to run',    type: 'text', required: true },
      ]},
    ],
  },
  {
    type: 'antifor', label: 'Anti-Forensics', color: '#ffb730',
    methods: [
      { method: 'timestomp',     label: 'Timestomp',          desc: 'Set file creation/modified/accessed times', args: [
        { key: 'path',     label: 'Target file',                    type: 'text', required: true },
        { key: 'modified', label: 'Modified (YYYY-MM-DD HH:MM:SS)', type: 'text', placeholder: '2020-01-01 00:00:00' },
        { key: 'created',  label: 'Created (optional)',             type: 'text' },
        { key: 'accessed', label: 'Accessed (optional)',            type: 'text' },
      ]},
      { method: 'eventlog-clear', label: 'Clear Event Log',   desc: 'EvtClearLog (needs admin)', args: [
        { key: 'log', label: 'Log name', type: 'select', required: true,
          options: ['Security','System','Application','Microsoft-Windows-PowerShell/Operational'] },
      ]},
      { method: 'eventlog-del',   label: 'Delete Event Record', desc: 'Delete single record by ID (needs admin)', args: [
        { key: 'log', label: 'Log name', type: 'text',   required: true, placeholder: 'Security' },
        { key: 'id',  label: 'Event ID', type: 'number', required: true },
      ]},
      { method: 'indicator-rm',   label: 'Secure Delete',     desc: 'Overwrite + DeleteFileW', args: [
        { key: 'path', label: 'File to delete', type: 'text', required: true },
      ]},
      { method: 'shadow-delete',  label: 'Delete Shadow Copies', desc: 'vssadmin delete shadows (needs admin)', args: [] },
    ],
  },
  {
    type: 'lateral', label: 'Lateral Movement', color: '#4090ff',
    methods: [
      { method: 'smb-psexec', label: 'SMB PsExec-style', desc: 'Remote SCM service create + exec', args: [
        { key: 'host', label: 'Target host', type: 'text', required: true },
        { key: 'cmd',  label: 'Command',     type: 'text', required: true },
      ]},
      { method: 'wmi',        label: 'WMI Remote Exec', desc: 'wmic remote process create', args: [
        { key: 'host', label: 'Target host',   type: 'text', required: true },
        { key: 'cmd',  label: 'Command',        type: 'text', required: true },
        { key: 'user', label: 'Username (opt)', type: 'text' },
        { key: 'pass', label: 'Password (opt)', type: 'text' },
      ]},
      { method: 'winrm',      label: 'WinRM Exec',      desc: 'winrs remote exec', args: [
        { key: 'host', label: 'Target host',   type: 'text', required: true },
        { key: 'cmd',  label: 'Command',        type: 'text', required: true },
        { key: 'user', label: 'Username (opt)', type: 'text' },
        { key: 'pass', label: 'Password (opt)', type: 'text' },
      ]},
      { method: 'dcom',       label: 'DCOM Exec',        desc: 'DCOM remote process', args: [
        { key: 'host', label: 'Target host', type: 'text', required: true },
        { key: 'cmd',  label: 'Command',     type: 'text', required: true },
      ]},
      { method: 'rdp-pth',    label: 'RDP Pass-the-Hash', desc: 'RDP via hash (Restricted Admin mode)', args: [
        { key: 'host', label: 'Target host', type: 'text', required: true },
        { key: 'user', label: 'Username',    type: 'text', required: true },
        { key: 'hash', label: 'NTLM hash',   type: 'text', required: true },
      ]},
      { method: 'adidns',     label: 'ADIDNS Abuse',     desc: 'Add/modify AD-integrated DNS record', args: [
        { key: 'record', label: 'Record name', type: 'text',   required: true },
        { key: 'ip',     label: 'IP address',  type: 'text',   required: true },
        { key: 'action', label: 'Action',      type: 'select', options: ['add','remove'], default: 'add' },
      ]},
    ],
  },
  {
    type: 'inject', label: 'Injection', color: '#b860ff',
    methods: [
      { method: 'classic', label: 'Classic Injection', desc: 'VirtualAllocEx + WriteProcessMemory + CreateRemoteThread', args: [
        { key: 'pid',       label: 'Target PID',        type: 'number',   required: true },
        { key: 'shellcode', label: 'Shellcode (base64)', type: 'textarea', required: true },
      ]},
      { method: 'apc',     label: 'APC Injection',     desc: 'Queue APC to thread in target process', args: [
        { key: 'pid',       label: 'Target PID',        type: 'number',   required: true },
        { key: 'shellcode', label: 'Shellcode (base64)', type: 'textarea', required: true },
      ]},
      { method: 'hollow',  label: 'Process Hollow',    desc: 'Create suspended process, hollow + inject', args: [
        { key: 'exe',       label: 'Host executable',   type: 'text',     required: true, placeholder: 'C:\\Windows\\System32\\svchost.exe' },
        { key: 'shellcode', label: 'Shellcode (base64)', type: 'textarea', required: true },
      ]},
      { method: 'hijack',  label: 'Thread Hijack',     desc: 'Suspend thread, redirect RIP, resume', args: [
        { key: 'pid',       label: 'Target PID',        type: 'number',   required: true },
        { key: 'shellcode', label: 'Shellcode (base64)', type: 'textarea', required: true },
      ]},
      { method: 'stomp',   label: 'Module Stomp',      desc: 'Overwrite mapped DLL with shellcode', args: [
        { key: 'pid',       label: 'Target PID',  type: 'number',   required: true },
        { key: 'dll',       label: 'DLL to stomp', type: 'text',     required: true, placeholder: 'amsi.dll' },
        { key: 'shellcode', label: 'Shellcode (base64)', type: 'textarea', required: true },
      ]},
    ],
  },
  {
    type: 'file', label: 'File Manager', color: '#60a8ff',
    methods: [
      { method: 'ls',    label: 'List Directory', desc: 'Directory listing', args: [
        { key: 'path', label: 'Path', type: 'text', required: true, placeholder: 'C:\\' },
      ]},
      { method: 'read',  label: 'Read File',      desc: 'Read file contents (base64 out)', args: [
        { key: 'path', label: 'File path', type: 'text', required: true },
      ]},
      { method: 'write', label: 'Write File',     desc: 'Write base64 content to path', args: [
        { key: 'path', label: 'Destination path', type: 'text',     required: true },
        { key: 'data', label: 'Content (base64)', type: 'textarea', required: true },
      ]},
      { method: 'rm',    label: 'Delete',         desc: 'Delete file or directory', args: [
        { key: 'path', label: 'Path', type: 'text', required: true },
      ]},
      { method: 'mkdir', label: 'Create Directory', desc: 'Create directory tree', args: [
        { key: 'path', label: 'Path', type: 'text', required: true },
      ]},
      { method: 'mv',    label: 'Move / Rename',  desc: 'Rename or move file', args: [
        { key: 'src', label: 'Source',      type: 'text', required: true },
        { key: 'dst', label: 'Destination', type: 'text', required: true },
      ]},
      { method: 'cp',    label: 'Copy',           desc: 'Copy file', args: [
        { key: 'src', label: 'Source',      type: 'text', required: true },
        { key: 'dst', label: 'Destination', type: 'text', required: true },
      ]},
      { method: 'info',  label: 'File Info',      desc: 'File metadata (size, times, attributes)', args: [
        { key: 'path', label: 'Path', type: 'text', required: true },
      ]},
    ],
  },
]

// ── Quick actions ─────────────────────────────────────────────────────────────

export const QUICK_ACTIONS: Array<{
  label:  string
  type:   string
  args:   Record<string, unknown>
}> = [
  { label: 'Dump LSASS (PSS)',    type: 'cred',    args: { method: 'lsass-pss' } },
  { label: 'Kerberoast',          type: 'cred',    args: { method: 'kerberoast' } },
  { label: 'DCSync (krbtgt)',     type: 'cred',    args: { method: 'dcsync', user: 'krbtgt' } },
  { label: 'Enum Processes',      type: 'enum',    args: { method: 'processes' } },
  { label: 'Dump Vault',          type: 'collect', args: { method: 'vault' } },
  { label: 'Browser Creds',       type: 'collect', args: { method: 'browser-creds' } },
  { label: 'Screenshot',          type: 'collect', args: { method: 'screen-record', count: 1 } },
  { label: 'Shadow Delete',       type: 'antifor', args: { method: 'shadow-delete' } },
]

// ── Component ─────────────────────────────────────────────────────────────────

interface Props {
  onSubmit: (type: string, args: Record<string, unknown>) => void
  onClose:  () => void
}

const inputStyle: React.CSSProperties = {
  width: '100%',
  background: 'var(--dm-bg)',
  border: '1px solid var(--dm-border)',
  color: 'var(--dm-text-hi)',
  fontFamily: 'inherit',
  fontSize: '0.8rem',
  padding: '0.3rem 0.5rem',
  outline: 'none',
  borderRadius: 0,
}

export function TaskBuilder({ onSubmit, onClose }: Props) {
  const [catIdx,    setCatIdx]    = useState(0)
  const [methodIdx, setMethodIdx] = useState(0)
  const [values,    setValues]    = useState<Record<string, string>>({})

  const cat    = SCHEMA[catIdx]
  const method = cat.methods[methodIdx]

  function selectCat(i: number) {
    setCatIdx(i)
    setMethodIdx(0)
    setValues({})
  }

  function selectMethod(i: number) {
    setMethodIdx(i)
    setValues({})
  }

  function setValue(key: string, val: string) {
    setValues(prev => ({ ...prev, [key]: val }))
  }

  function submit() {
    const missing = method.args.filter(a => a.required && !values[a.key]?.trim() && !a.default)
    if (missing.length > 0) {
      alert(`Required: ${missing.map(a => a.label).join(', ')}`)
      return
    }
    const args: Record<string, unknown> = { method: method.method }
    for (const a of method.args) {
      const v = values[a.key] ?? a.default ?? ''
      if (!v) continue
      args[a.key] = a.type === 'number' ? Number(v) : v
    }
    onSubmit(cat.type, args)
    onClose()
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center"
      style={{ background: 'rgba(0,0,0,0.75)' }}
      onClick={onClose}
    >
      <div
        className="flex flex-col"
        style={{
          width: '860px',
          maxWidth: '95vw',
          height: '560px',
          maxHeight: '90vh',
          background: 'var(--dm-surface)',
          border: '1px solid var(--dm-border-hi)',
          boxShadow: '0 24px 64px rgba(0,0,0,0.6)',
        }}
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div
          className="flex items-center justify-between flex-shrink-0 px-4 py-2"
          style={{ borderBottom: '1px solid var(--dm-border)', minHeight: '38px' }}
        >
          <span style={{ color: 'var(--dm-text-hi)', fontWeight: 600, fontSize: '0.82rem', letterSpacing: '0.06em' }}>
            TASK BUILDER
          </span>
          <button
            onClick={onClose}
            style={{ color: 'var(--dm-text-lo)', background: 'none', border: 'none', cursor: 'pointer', padding: '2px' }}
            onMouseEnter={e => (e.currentTarget.style.color = 'var(--dm-text-hi)')}
            onMouseLeave={e => (e.currentTarget.style.color = 'var(--dm-text-lo)')}
          >
            <X size={14} />
          </button>
        </div>

        {/* Body — 3 columns */}
        <div className="flex flex-1 min-h-0">

          {/* Col 1: Categories */}
          <div
            className="flex flex-col flex-shrink-0 overflow-y-auto"
            style={{ width: '150px', borderRight: '1px solid var(--dm-border)' }}
          >
            {SCHEMA.map((c, i) => (
              <button
                key={c.type}
                onClick={() => selectCat(i)}
                style={{
                  textAlign: 'left',
                  padding: '0.5rem 0.75rem',
                  background: i === catIdx ? 'var(--dm-bg)' : 'none',
                  border: 'none',
                  borderLeft: i === catIdx ? `2px solid ${c.color}` : '2px solid transparent',
                  color: i === catIdx ? 'var(--dm-text-hi)' : 'var(--dm-text-lo)',
                  fontSize: '0.75rem',
                  cursor: 'pointer',
                  fontFamily: 'inherit',
                  transition: 'color 0.1s',
                }}
                onMouseEnter={e => { if (i !== catIdx) e.currentTarget.style.color = 'var(--dm-text-mid)' }}
                onMouseLeave={e => { if (i !== catIdx) e.currentTarget.style.color = 'var(--dm-text-lo)' }}
              >
                {c.label}
              </button>
            ))}
          </div>

          {/* Col 2: Methods */}
          <div
            className="flex flex-col flex-shrink-0 overflow-y-auto"
            style={{ width: '200px', borderRight: '1px solid var(--dm-border)' }}
          >
            {cat.methods.map((m, i) => (
              <button
                key={m.method}
                onClick={() => selectMethod(i)}
                style={{
                  textAlign: 'left',
                  padding: '0.45rem 0.75rem',
                  background: i === methodIdx ? 'var(--dm-bg)' : 'none',
                  border: 'none',
                  borderLeft: i === methodIdx ? `2px solid ${cat.color}` : '2px solid transparent',
                  color: i === methodIdx ? 'var(--dm-text-hi)' : 'var(--dm-text-lo)',
                  fontSize: '0.75rem',
                  cursor: 'pointer',
                  fontFamily: 'inherit',
                  transition: 'color 0.1s',
                  lineHeight: '1.3',
                }}
                onMouseEnter={e => { if (i !== methodIdx) e.currentTarget.style.color = 'var(--dm-text-mid)' }}
                onMouseLeave={e => { if (i !== methodIdx) e.currentTarget.style.color = 'var(--dm-text-lo)' }}
              >
                {m.label}
              </button>
            ))}
          </div>

          {/* Col 3: Arg form */}
          <div className="flex flex-col flex-1 min-w-0 overflow-y-auto p-4 gap-3">
            <div>
              <div style={{ color: 'var(--dm-text-hi)', fontWeight: 600, fontSize: '0.84rem', marginBottom: '4px' }}>
                {cat.type}/{method.method}
              </div>
              <div style={{ color: 'var(--dm-text-lo)', fontSize: '0.72rem' }}>{method.desc}</div>
            </div>

            {method.args.length === 0 ? (
              <div style={{ color: 'var(--dm-text-lo)', fontSize: '0.75rem', fontStyle: 'italic' }}>
                No arguments required.
              </div>
            ) : (
              method.args.map(a => (
                <div key={a.key}>
                  <label style={{ display: 'block', color: 'var(--dm-text-mid)', fontSize: '0.7rem', marginBottom: '4px', letterSpacing: '0.04em' }}>
                    {a.label}{a.required && <span style={{ color: 'var(--dm-red)' }}> *</span>}
                  </label>
                  {a.type === 'textarea' ? (
                    <textarea
                      value={values[a.key] ?? ''}
                      onChange={e => setValue(a.key, e.target.value)}
                      placeholder={a.placeholder}
                      rows={3}
                      style={{ ...inputStyle, resize: 'vertical', fontFamily: 'Consolas, monospace', fontSize: '0.72rem' }}
                    />
                  ) : a.type === 'select' ? (
                    <select
                      value={values[a.key] ?? a.default ?? ''}
                      onChange={e => setValue(a.key, e.target.value)}
                      style={{ ...inputStyle }}
                    >
                      {a.options!.map(o => <option key={o} value={o}>{o}</option>)}
                    </select>
                  ) : (
                    <input
                      type={a.type === 'number' ? 'number' : 'text'}
                      value={values[a.key] ?? a.default ?? ''}
                      onChange={e => setValue(a.key, e.target.value)}
                      placeholder={a.placeholder}
                      style={inputStyle}
                    />
                  )}
                </div>
              ))
            )}
          </div>
        </div>

        {/* Footer */}
        <div
          className="flex items-center justify-between flex-shrink-0 px-4 py-2"
          style={{ borderTop: '1px solid var(--dm-border)' }}
        >
          <span style={{ color: 'var(--dm-text-lo)', fontSize: '0.68rem', fontFamily: 'Consolas, monospace' }}>
            {cat.type}/{method.method}
          </span>
          <div className="flex gap-2">
            <button
              className="dm-action"
              onClick={onClose}
              style={{ color: 'var(--dm-text-lo)', borderColor: 'var(--dm-border)' }}
            >
              Cancel
            </button>
            <button className="dm-action dm-go" onClick={submit}>
              Queue Task
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
