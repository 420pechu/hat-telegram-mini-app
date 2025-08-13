const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

class Database {
    constructor() {
        const persistentDir = process.env.PERSISTENT_DIR || path.join(__dirname, '../persistent');
        const dbDir = path.join(persistentDir, 'data');
        if (!fs.existsSync(persistentDir)) fs.mkdirSync(persistentDir, { recursive: true });
        if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });
        this.dbPath = path.join(dbDir, 'gallery.db');
        this.db = new sqlite3.Database(this.dbPath);
        this.init();
    }

    init() {
        return new Promise((resolve) => {
            this.db.serialize(() => {
                this.db.run(`
                    CREATE TABLE IF NOT EXISTS images (
                        id TEXT PRIMARY KEY,
                        userId TEXT NOT NULL,
                        userName TEXT NOT NULL,
                        filename TEXT NOT NULL,
                        originalName TEXT,
                        size INTEGER,
                        mimeType TEXT,
                        createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
                        likes INTEGER DEFAULT 0
                    )
                `);
                this.db.run(`
                    CREATE TABLE IF NOT EXISTS likes (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        imageId TEXT NOT NULL,
                        userId TEXT NOT NULL,
                        createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(imageId, userId)
                    )
                `, () => resolve());
            });
        });
    }

    generateId() {
        return Date.now().toString() + Math.random().toString(36).substr(2, 9);
    }

    async createImage(imageData) {
        return new Promise((resolve, reject) => {
            const id = this.generateId();
            const { userId, userName, filename, originalName, size, mimeType } = imageData;
            this.db.run(`
                INSERT INTO images (id, userId, userName, filename, originalName, size, mimeType)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            `, [id, userId, userName, filename, originalName, size, mimeType], function(err) {
                if (err) return reject(err);
                resolve(id);
            });
        });
    }

    async getAllImages(limit = 50, sortBy = 'likes') {
        return new Promise((resolve, reject) => {
            const orderClause = sortBy === 'recent' ? 'ORDER BY createdAt DESC, likes DESC' : 'ORDER BY likes DESC, createdAt DESC';
            this.db.all(`
                SELECT id, userId, userName, filename, originalName, createdAt, likes
                FROM images
                ${orderClause}
                LIMIT ?
            `, [limit], (err, rows) => {
                if (err) return reject(err);
                resolve(rows);
            });
        });
    }

    async getImageById(imageId) {
        return new Promise((resolve, reject) => {
            this.db.get(`SELECT * FROM images WHERE id = ?`, [imageId], (err, row) => {
                if (err) return reject(err);
                resolve(row);
            });
        });
    }

    async toggleLike(imageId, userId) {
        return new Promise((resolve, reject) => {
            this.db.get(`SELECT id FROM likes WHERE imageId = ? AND userId = ?`, [imageId, userId], (err, row) => {
                if (err) return reject(err);
                if (row) {
                    this.db.run(`DELETE FROM likes WHERE imageId = ? AND userId = ?`, [imageId, userId], (err2) => {
                        if (err2) return reject(err2);
                        this.db.run(`UPDATE images SET likes = likes - 1 WHERE id = ?`, [imageId], (err3) => {
                            if (err3) return reject(err3);
                            this.db.get(`SELECT likes FROM images WHERE id = ?`, [imageId], (err4, r) => {
                                if (err4) return reject(err4);
                                resolve({ liked: false, totalLikes: r.likes });
                            });
                        });
                    });
                } else {
                    this.db.run(`INSERT INTO likes (imageId, userId) VALUES (?, ?)`, [imageId, userId], (err2) => {
                        if (err2) return reject(err2);
                        this.db.run(`UPDATE images SET likes = likes + 1 WHERE id = ?`, [imageId], (err3) => {
                            if (err3) return reject(err3);
                            this.db.get(`SELECT likes FROM images WHERE id = ?`, [imageId], (err4, r) => {
                                if (err4) return reject(err4);
                                resolve({ liked: true, totalLikes: r.likes });
                            });
                        });
                    });
                }
            });
        });
    }

    async deleteImage(imageId) {
        return new Promise((resolve, reject) => {
            this.db.run(`DELETE FROM images WHERE id = ?`, [imageId], function(err) {
                if (err) return reject(err);
                resolve(this.changes > 0);
            });
        });
    }
}

module.exports = Database;


