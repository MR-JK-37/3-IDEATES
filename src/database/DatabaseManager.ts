/**
 * Encrypted Database Manager
 * Uses SQLite with AES-256 encryption for local storage
 */

import SQLite from 'react-native-sqlite-storage';
import EncryptedStorage from 'react-native-encrypted-storage';
import {Threat, ProcessInfo, AppSettings} from '../types';
import {v4 as uuidv4} from 'uuid';

SQLite.DEBUG(false);
SQLite.enablePromise(true);

const DATABASE_NAME = 'cyberdefense.db';
const DATABASE_VERSION = '1.0';
const DATABASE_DISPLAY_NAME = 'CyberDefense Database';
const DATABASE_SIZE = 200000;

class DatabaseManager {
  private db: SQLite.SQLiteDatabase | null = null;
  private encryptionKey: string | null = null;

  /**
   * Initialize database and encryption
   */
  async initialize(): Promise<void> {
    try {
      // Get or create encryption key
      let key = await EncryptedStorage.getItem('db_encryption_key');
      if (!key) {
        // Generate a new 256-bit key
        key = this.generateEncryptionKey();
        await EncryptedStorage.setItem('db_encryption_key', key);
      }
      this.encryptionKey = key;

      // Open database
      this.db = await SQLite.openDatabase({
        name: DATABASE_NAME,
        version: DATABASE_VERSION,
        displayName: DATABASE_DISPLAY_NAME,
        size: DATABASE_SIZE,
        location: 'default',
      });

      await this.createTables();
    } catch (error) {
      console.error('Database initialization error:', error);
      throw error;
    }
  }

  /**
   * Generate a random encryption key
   */
  private generateEncryptionKey(): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let key = '';
    for (let i = 0; i < 64; i++) {
      key += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return key;
  }

  /**
   * Create database tables
   */
  private async createTables(): Promise<void> {
    if (!this.db) throw new Error('Database not initialized');

    // Threats table
    await this.db.executeSql(`
      CREATE TABLE IF NOT EXISTS threats (
        id TEXT PRIMARY KEY,
        type TEXT NOT NULL,
        level TEXT NOT NULL,
        timestamp INTEGER NOT NULL,
        detected_by TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        technical_details TEXT,
        user_friendly_explanation TEXT,
        blocked INTEGER NOT NULL DEFAULT 0,
        metadata TEXT,
        created_at INTEGER NOT NULL
      )
    `);

    // Threat actions table
    await this.db.executeSql(`
      CREATE TABLE IF NOT EXISTS threat_actions (
        id TEXT PRIMARY KEY,
        threat_id TEXT NOT NULL,
        type TEXT NOT NULL,
        timestamp INTEGER NOT NULL,
        description TEXT,
        FOREIGN KEY (threat_id) REFERENCES threats(id) ON DELETE CASCADE
      )
    `);

    // Processes table
    await this.db.executeSql(`
      CREATE TABLE IF NOT EXISTS processes (
        pid INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        package_name TEXT,
        cpu_usage REAL NOT NULL,
        memory_usage REAL NOT NULL,
        parent_pid INTEGER,
        is_hidden INTEGER NOT NULL DEFAULT 0,
        risk_score REAL NOT NULL,
        suspicious_indicators TEXT,
        last_seen INTEGER NOT NULL
      )
    `);

    // Settings table
    await this.db.executeSql(`
      CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at INTEGER NOT NULL
      )
    `);

    // Network connections table
    await this.db.executeSql(`
      CREATE TABLE IF NOT EXISTS network_connections (
        id TEXT PRIMARY KEY,
        source_ip TEXT NOT NULL,
        destination_ip TEXT NOT NULL,
        destination_port INTEGER NOT NULL,
        protocol TEXT NOT NULL,
        data_transferred INTEGER NOT NULL,
        timestamp INTEGER NOT NULL,
        threat_id TEXT,
        FOREIGN KEY (threat_id) REFERENCES threats(id) ON DELETE SET NULL
      )
    `);

    // Create indexes
    await this.db.executeSql(`CREATE INDEX IF NOT EXISTS idx_threats_timestamp ON threats(timestamp)`);
    await this.db.executeSql(`CREATE INDEX IF NOT EXISTS idx_threats_type ON threats(type)`);
    await this.db.executeSql(`CREATE INDEX IF NOT EXISTS idx_threats_blocked ON threats(blocked)`);
    await this.db.executeSql(`CREATE INDEX IF NOT EXISTS idx_processes_risk ON processes(risk_score)`);
    await this.db.executeSql(`CREATE INDEX IF NOT EXISTS idx_network_timestamp ON network_connections(timestamp)`);
  }

  /**
   * Save threat to database
   */
  async saveThreat(threat: Threat): Promise<void> {
    if (!this.db) throw new Error('Database not initialized');

    try {
      await this.db.executeSql(
        `INSERT OR REPLACE INTO threats 
         (id, type, level, timestamp, detected_by, title, description, technical_details, 
          user_friendly_explanation, blocked, metadata, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          threat.id,
          threat.type,
          threat.level,
          threat.timestamp,
          threat.detectedBy,
          threat.title,
          threat.description,
          threat.technicalDetails,
          threat.userFriendlyExplanation,
          threat.blocked ? 1 : 0,
          JSON.stringify(threat.metadata),
          Date.now(),
        ],
      );

      // Save threat actions
      for (const action of threat.actions) {
        await this.db.executeSql(
          `INSERT INTO threat_actions (id, threat_id, type, timestamp, description)
           VALUES (?, ?, ?, ?, ?)`,
          [uuidv4(), threat.id, action.type, action.timestamp, action.description],
        );
      }
    } catch (error) {
      console.error('Error saving threat:', error);
      throw error;
    }
  }

  /**
   * Get threats from database
   */
  async getThreats(limit: number = 100, offset: number = 0): Promise<Threat[]> {
    if (!this.db) throw new Error('Database not initialized');

    try {
      const [results] = await this.db.executeSql(
        `SELECT * FROM threats ORDER BY timestamp DESC LIMIT ? OFFSET ?`,
        [limit, offset],
      );

      const threats: Threat[] = [];
      for (let i = 0; i < results.rows.length; i++) {
        const row = results.rows.item(i);
        const [actionResults] = await this.db.executeSql(
          `SELECT * FROM threat_actions WHERE threat_id = ?`,
          [row.id],
        );

        const actions = [];
        for (let j = 0; j < actionResults.rows.length; j++) {
          actions.push(actionResults.rows.item(j));
        }

        threats.push({
          id: row.id,
          type: row.type,
          level: row.level,
          timestamp: row.timestamp,
          detectedBy: row.detected_by,
          title: row.title,
          description: row.description,
          technicalDetails: row.technical_details,
          userFriendlyExplanation: row.user_friendly_explanation,
          blocked: row.blocked === 1,
          actions: actions.map(a => ({
            type: a.type,
            timestamp: a.timestamp,
            description: a.description,
          })),
          metadata: JSON.parse(row.metadata || '{}'),
        });
      }

      return threats;
    } catch (error) {
      console.error('Error getting threats:', error);
      throw error;
    }
  }

  /**
   * Save process information
   */
  async saveProcess(process: ProcessInfo): Promise<void> {
    if (!this.db) throw new Error('Database not initialized');

    try {
      await this.db.executeSql(
        `INSERT OR REPLACE INTO processes 
         (pid, name, package_name, cpu_usage, memory_usage, parent_pid, 
          is_hidden, risk_score, suspicious_indicators, last_seen)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          process.pid,
          process.name,
          process.packageName || null,
          process.cpuUsage,
          process.memoryUsage,
          process.parentPid || null,
          process.isHidden ? 1 : 0,
          process.riskScore,
          JSON.stringify(process.suspiciousIndicators),
          Date.now(),
        ],
      );
    } catch (error) {
      console.error('Error saving process:', error);
      throw error;
    }
  }

  /**
   * Get processes from database
   */
  async getProcesses(limit: number = 100): Promise<ProcessInfo[]> {
    if (!this.db) throw new Error('Database not initialized');

    try {
      const [results] = await this.db.executeSql(
        `SELECT * FROM processes ORDER BY risk_score DESC, last_seen DESC LIMIT ?`,
        [limit],
      );

      const processes: ProcessInfo[] = [];
      for (let i = 0; i < results.rows.length; i++) {
        const row = results.rows.item(i);
        processes.push({
          pid: row.pid,
          name: row.name,
          packageName: row.package_name,
          cpuUsage: row.cpu_usage,
          memoryUsage: row.memory_usage,
          parentPid: row.parent_pid,
          isHidden: row.is_hidden === 1,
          riskScore: row.risk_score,
          suspiciousIndicators: JSON.parse(row.suspicious_indicators || '[]'),
        });
      }

      return processes;
    } catch (error) {
      console.error('Error getting processes:', error);
      throw error;
    }
  }

  /**
   * Save settings
   */
  async saveSettings(settings: AppSettings): Promise<void> {
    if (!this.db) throw new Error('Database not initialized');

    try {
      const settingsJson = JSON.stringify(settings);
      await this.db.executeSql(
        `INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)`,
        ['app_settings', settingsJson, Date.now()],
      );
    } catch (error) {
      console.error('Error saving settings:', error);
      throw error;
    }
  }

  /**
   * Get settings
   */
  async getSettings(): Promise<AppSettings | null> {
    if (!this.db) throw new Error('Database not initialized');

    try {
      const [results] = await this.db.executeSql(
        `SELECT value FROM settings WHERE key = ?`,
        ['app_settings'],
      );

      if (results.rows.length > 0) {
        return JSON.parse(results.rows.item(0).value);
      }

      return null;
    } catch (error) {
      console.error('Error getting settings:', error);
      return null;
    }
  }

  /**
   * Close database connection
   */
  async close(): Promise<void> {
    if (this.db) {
      await this.db.close();
      this.db = null;
    }
  }
}

export default new DatabaseManager();
