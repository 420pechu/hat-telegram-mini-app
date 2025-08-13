const Database = require('./models/database');
const fs = require('fs');
const path = require('path');

async function setup() {
    try {
        const db = new Database();
        await new Promise(r => setTimeout(r, 500));
        const persistentDir = process.env.PERSISTENT_DIR || path.join(__dirname, 'persistent');
        const uploadsDir = path.join(persistentDir, 'uploads');
        if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
        await db.init();
    } catch (e) {
        console.error('Setup failed', e);
        process.exit(1);
    }
}

if (require.main === module) {
    setup();
}

module.exports = setup;


