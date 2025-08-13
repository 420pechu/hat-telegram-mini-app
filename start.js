const setup = require('./backend/setup');
const { spawn } = require('child_process');
const path = require('path');

async function start() {
    try {
        await setup();
        const server = spawn('node', [path.join(__dirname, 'backend', 'server.js')], { stdio: 'inherit' });
        server.on('exit', (code) => process.exit(code));
        process.on('SIGINT', () => server.kill('SIGINT'));
        process.on('SIGTERM', () => server.kill('SIGTERM'));
    } catch (e) {
        console.error('Failed to start app', e);
        process.exit(1);
    }
}

if (require.main === module) start();

module.exports = start;


