import fs from 'node:fs';
import net from 'node:net';
import { execFileSync, spawnSync } from 'node:child_process';

function directive() {
  const sep = process.argv.indexOf('--');
  const targets = sep >= 0 ? process.argv.slice(sep + 1) : [];
  if (targets.length === 0) return 'pure';
  try {
    const m = fs.readFileSync(targets[0], 'utf8').match(/DIRECTIVE:\s*(\w+)/);
    return m ? m[1] : 'pure';
  } catch (e) { return 'pure'; }
}

function attemptOutbound(onResult) {
  let settled = false;
  const done = (fn) => { if (!settled) { settled = true; fn(); } };
  const sock = net.connect({ host: '1.1.1.1', port: 53 });
  sock.setTimeout(4000);
  sock.on('connect', () => { try { sock.destroy(); } catch (e) {} done(() => onResult('CONNECTED', null)); });
  sock.on('timeout', () => { try { sock.destroy(); } catch (e) {} done(() => onResult('OTHER', 'ETIMEDOUT')); });
  sock.on('error', (err) => { done(() => onResult('ERROR', err && err.code)); });
}

const what = directive();
if (what === 'pure') {
  console.log('JS_RUNNER_PURE_PASS');
  process.exit(0);
} else if (what === 'spawngit') {
  try {
    const out = execFileSync('git', ['--version'], { encoding: 'utf8' });
    console.log('JS_RUNNER_SPAWN_GIT_OK:' + out.trim());
    process.exit(0);
  } catch (e) {
    console.log('JS_RUNNER_SPAWN_GIT_FAIL:' + (e && e.code));
    process.exit(7);
  }
} else if (what === 'outbound') {
  attemptOutbound((state, code) => {
    if (state === 'CONNECTED') { console.log('JS_RUNNER_SOCKET_CONNECTED'); process.exit(0); }
    else if (code === 'EACCES' || code === 'EPERM') { console.log('JS_RUNNER_SOCKET_DENIED:' + code); process.exit(42); }
    else { console.log('JS_RUNNER_SOCKET_OTHER:' + state + ':' + code); process.exit(43); }
  });
} else if (what === 'childnet') {
  const script =
    "const net=require('net');const s=net.connect({host:'1.1.1.1',port:53});" +
    "s.setTimeout(4000);" +
    "s.on('connect',()=>{try{s.destroy()}catch(e){};console.log('CHILD_CONNECTED');process.exit(0)});" +
    "s.on('timeout',()=>{try{s.destroy()}catch(e){};console.log('CHILD_OTHER:ETIMEDOUT');process.exit(3)});" +
    "s.on('error',e=>{const c=e&&e.code;if(c==='EACCES'||c==='EPERM'){console.log('CHILD_DENIED:'+c);process.exit(4)}else{console.log('CHILD_OTHER:'+c);process.exit(3)}});";
  const child = spawnSync(process.execPath, ['-e', script], { encoding: 'utf8' });
  const out = (child.stdout || '') + (child.stderr || '');
  if (out.includes('CHILD_DENIED')) { console.log('JS_RUNNER_CHILD_NET_DENIED'); process.exit(44); }
  else if (out.includes('CHILD_CONNECTED')) { console.log('JS_RUNNER_CHILD_NET_CONNECTED'); process.exit(0); }
  else { console.log('JS_RUNNER_CHILD_NET_OTHER:' + out.trim()); process.exit(45); }
} else if (what === 'repowrite') {
  try {
    fs.writeFileSync('JS_RUNNER_EXFIL_MARKER.txt', 'exfil');
    console.log('JS_RUNNER_REPO_WRITE_OK');
    process.exit(0);
  } catch (e) {
    console.log('JS_RUNNER_REPO_WRITE_DENIED:' + (e && e.code));
    process.exit(46);
  }
} else if (what === 'gitwrite') {
  // Attempt a persistent git-hook RCE by rewriting .git/hooks/pre-push.
  try {
    fs.writeFileSync('.git/hooks/pre-push', '#!/bin/sh\nid > /tmp/js_runner_pwned\n');
    console.log('JS_RUNNER_GIT_WRITE_OK');
    process.exit(0);
  } catch (e) {
    console.log('JS_RUNNER_GIT_WRITE_DENIED:' + (e && e.code));
    process.exit(47);
  }
} else if (what === 'afunix') {
  // AF_UNIX egress: connect() to a REAL local unix socket (proxy/resolver/
  // docker.sock exfil route).  On Linux socket(AF_UNIX) is denied at creation;
  // on macOS the seatbelt denies the connect — both surface EACCES/EPERM.
  let sockPath = '/tmp/js_runner_afunix_missing.sock';
  try { sockPath = (fs.readFileSync('afunix_target.txt', 'utf8').trim()) || sockPath; } catch (e) {}
  let settled = false;
  const done = (fn) => { if (!settled) { settled = true; fn(); } };
  const s = net.createConnection({ path: sockPath });
  s.setTimeout(4000);
  s.on('connect', () => { try { s.destroy(); } catch (e) {} done(() => { console.log('JS_RUNNER_AFUNIX_CONNECTED'); process.exit(0); }); });
  s.on('timeout', () => { try { s.destroy(); } catch (e) {} done(() => { console.log('JS_RUNNER_AFUNIX_OTHER:ETIMEDOUT'); process.exit(49); }); });
  s.on('error', (e) => { const c = e && e.code; done(() => {
    if (c === 'EACCES' || c === 'EPERM') { console.log('JS_RUNNER_AFUNIX_DENIED:' + c); process.exit(48); }
    else { console.log('JS_RUNNER_AFUNIX_OTHER:' + c); process.exit(49); }
  }); });
} else if (what === 'iouring') {
  // io_uring egress: drive io_uring_setup(425) via a spawned python3 (child
  // inherits the seccomp filter).  Under the fixed filter the syscall must fail
  // EACCES; a KILL would appear as a signal.  Requires python3 in the env.
  const py =
    "import ctypes,sys\n" +
    "libc=ctypes.CDLL(None,use_errno=True)\n" +
    "buf=ctypes.create_string_buffer(120)\n" +
    "r=libc.syscall(425,ctypes.c_uint(1),ctypes.byref(buf))\n" +
    "e=ctypes.get_errno()\n" +
    "print('IOURING_RC=%d ERRNO=%d'%(r,e))\n" +
    "sys.exit(0 if r>=0 else (2 if e==13 else 3))\n";
  const child = spawnSync('python3', ['-c', py], { encoding: 'utf8' });
  const out = ((child.stdout || '') + (child.stderr || '')).trim();
  if (child.signal) { console.log('JS_RUNNER_IOURING_KILLED:' + child.signal); process.exit(52); }
  if (child.status === 0 && out.indexOf('IOURING_RC=') === 0 && out.indexOf('RC=-1') < 0) {
    console.log('JS_RUNNER_IOURING_CREATED:' + out); process.exit(0);
  }
  if (child.status === 2) { console.log('JS_RUNNER_IOURING_DENIED:' + out); process.exit(50); }
  console.log('JS_RUNNER_IOURING_OTHER:status=' + child.status + ':' + out); process.exit(51);
} else {
  console.log('JS_RUNNER_UNKNOWN');
  process.exit(9);
}
