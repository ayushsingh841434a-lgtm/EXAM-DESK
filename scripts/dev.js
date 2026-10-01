const { spawn } = require('node:child_process');

const npmCli = process.env.npm_execpath;
if (!npmCli) {
  console.error('Start this launcher with `npm run dev` so npm can locate its CLI.');
  process.exit(1);
}

const children = ['dev:backend', 'dev:frontend'].map((script) => {
  const child = spawn(process.execPath, [npmCli, 'run', script], {
    stdio: 'inherit',
  });

  child.on('error', (error) => {
    console.error(`Could not start ${script}:`, error.message);
    stopChildren(1);
  });

  child.on('exit', (code) => {
    if (!stopping) stopChildren(code || 0);
  });

  return child;
});

let stopping = false;

function stopChildren(exitCode = 0) {
  if (stopping) return;
  stopping = true;
  for (const child of children) {
    if (child.exitCode === null) child.kill();
  }
  process.exitCode = exitCode;
}

process.on('SIGINT', () => stopChildren(0));
process.on('SIGTERM', () => stopChildren(0));