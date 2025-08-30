const express = require("express");
const path = require("path");
const mongoose = require("mongoose");
const readline = require("readline");
const { spawn } = require("child_process");
const cron = require("node-cron");
const axios = require('axios');
require('dotenv').config();

// --- Database Models ---
// Note: We define schemas dynamically, so we don't import the models directly here.

/**
 * Enhanced Multi-Source Threat Intelligence Monitoring Application
 * Handles IP, SHA256, MD5, Hostname, and Domain indicators
 */
class ThreatIntelligenceApp {
  constructor() {
    this.expressApp = express();
    this.expressApp.use(express.json({ limit: "50mb" }));
    this.expressApp.use(express.urlencoded({ extended: true, limit: "50mb" }));
    this.expressApp.use(express.static(path.join(__dirname, "public")));


    // Data source configurations
    this.dataSources = [
      { type: 'ip', url: process.env.IP_FETCH_URL, dbName: 'ipMonitoringDB', chunkSize: 15000, batchSize: 500, validator: this.isValidIP.bind(this) },
      { type: 'sha256', url: process.env.SHA256_FETCH_URL, dbName: 'sha256MonitoringDB', chunkSize: 15000, batchSize: 500, validator: this.isValidSHA256.bind(this) },
      { type: 'md5', url: process.env.MD5_FETCH_URL, dbName: 'md5MonitoringDB', chunkSize: 15000, batchSize: 500, validator: this.isValidMD5.bind(this) },
      { type: 'hostname', url: process.env.HOSTNAME_FETCH_URL, dbName: 'hostnameMonitoringDB', chunkSize: 15000, batchSize: 500, validator: this.isValidHostname.bind(this) },
      { type: 'domain', url: process.env.DOMAIN_FETCH_URL, dbName: 'domainMonitoringDB', chunkSize: 15000, batchSize: 500, validator: this.isValidDomain.bind(this) }
    ];

    this.isProcessing = false;
    this.connections = new Map(); // Store database connections
    this.processingStats = {
        lastRun: null,
        details: {} // Will store stats per type
    };
  }

  async initialize() {
    try {
      console.log("🚀 Initializing Multi-Source Threat Intelligence Application...");
      await this.initializeDatabaseConnections();
      this.setupExpress();
      await this.showInitialStats();
      this.setupScheduler();
      this.setupCLI();
      this.setupGracefulShutdown();
      console.log("✅ Application initialized successfully!");
      console.log("📋 Available commands: r, s, d, process, q");
      console.log("⏰ Scheduled to run daily at midnight (00:00)");
    } catch (error) {
      console.error("❌ Failed to initialize application:", error.message);
      process.exit(1);
    }
  }

  async initializeDatabaseConnections() {
    for (const source of this.dataSources) {
      try {
        const connection = await mongoose.createConnection(
          process.env.MONGODB_URI.replace(/\/\w*$/, `/${source.dbName}`),
          { maxPoolSize: 10, serverSelectionTimeoutMS: 5000, socketTimeoutMS: 45000 }
        );
        this.connections.set(source.type, connection);
        console.log(`✅ Connected to ${source.type} database: ${source.dbName}`);
      } catch (error) {
        console.error(`❌ Failed to connect to ${source.type} database:`, error.message);
        throw error;
      }
    }
  }

  setupScheduler() {
    cron.schedule('0 0 * * *', async () => {
      console.log("🕛 Midnight scheduler triggered - Starting daily processing...");
      await this.processAllSources();
    }, { timezone: "Asia/Dhaka" });
    console.log("⏰ Cron scheduler initialized for daily midnight processing");
  }

  async processAllSources() {
    if (this.isProcessing) {
        console.log("⚠️ Processing already in progress, skipping...");
        return;
    }
    this.isProcessing = true;
    
    // Initialize stats structure for the current run
    this.processingStats = { lastRun: new Date(), details: {} };
    this.dataSources.forEach(source => {
        this.processingStats.details[source.type] = { fetched: 0, inserted: 0, duplicates: 0 };
    });

    const startTime = Date.now();

    try {
        // --- PHASE 1: FETCH AND STORE ALL INDICATORS ---
        console.log("\n" + "🔄".repeat(20));
        console.log("🔄 PHASE 1: FETCHING & STORING ALL INDICATORS");
        console.log("🔄".repeat(20));

        for (const source of this.dataSources) {
            try {
                console.log(`\n📥 Fetching from ${source.type.toUpperCase()}...`);
                const indicators = await this.fetchIndicators(source);
                if (indicators.length === 0) {
                    console.log(`  - No new indicators found.`);
                    continue;
                }
                this.processingStats.details[source.type].fetched = indicators.length;
                console.log(`  - Fetched ${indicators.length.toLocaleString()} unique indicators.`);
                
                const storedCount = await this.storeIndicators(source, indicators);
                this.processingStats.details[source.type].inserted = storedCount;
                this.processingStats.details[source.type].duplicates = indicators.length - storedCount;
                console.log(`  - Stored ${storedCount.toLocaleString()} new indicators.`);
            } catch (error) {
                console.error(`❌ Error during fetch/store for ${source.type}:`, error.message);
            }
        }

        // --- PHASE 2: ANALYZE NEW INDICATORS WITH MISP ---
        console.log("\n" + "🛡️".repeat(20));
        console.log("🛡️ PHASE 2: ANALYZING NEW INDICATORS WITH MISP");
        console.log("🛡️".repeat(20));

        for (const source of this.dataSources) {
            try {
                const analyzed = await this.analyzeWithMISP(source);
                if (analyzed > 0) {
                    console.log(`\n  - Analyzed ${analyzed.toLocaleString()} new ${source.type.toUpperCase()} indicators.`);
                } else {
                    console.log(`\n  - No new indicators to analyze for ${source.type.toUpperCase()}.`);
                }
            } catch (error) {
                console.error(`❌ Error during MISP analysis for ${source.type}:`, error.message);
            }
        }

        const duration = ((Date.now() - startTime) / 1000 / 60).toFixed(2);
        console.log("\n" + "✅".repeat(20));
        console.log("✅ COMPREHENSIVE PROCESSING COMPLETED");
        console.log("✅".repeat(20));
        console.log(`⏱️ Total duration: ${duration} minutes`);
    } catch (error) {
        console.error("💥 Critical error during processing:", error.message);
    } finally {
        this.isProcessing = false;
    }
  }

  async fetchIndicators(source) {
    try {
      const response = await axios.get(source.url, { timeout: 60000, headers: { 'User-Agent': 'ThreatIntel-Monitor/2.0', 'Accept': 'text/plain' } });
      if (response.status !== 200) throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      const rawData = response.data.split('\n').map(line => line.trim()).filter(line => line && !line.startsWith('#')).filter(indicator => source.validator(indicator));
      return [...new Set(rawData)];
    } catch (error) {
      return [];
    }
  }

  async storeIndicators(source, indicators) {
    const connection = this.connections.get(source.type);
    const ThreatIndicatorModel = require('./models/ThreatIndicator')(connection);
    let storedCount = 0;
    const chunkSize = source.chunkSize;
    const totalChunks = Math.ceil(indicators.length / chunkSize);
    
    // **FIX**: Add an initial log to show the process has started
    console.log(`  - Storing ${indicators.length.toLocaleString()} indicators in ${totalChunks} chunks...`);

    for (let i = 0; i < totalChunks; i++) {
      const chunk = indicators.slice(i * chunkSize, (i + 1) * chunkSize);
      try {
        // **FIX**: Update progress more frequently
        if ((i + 1) % 10 === 0 || i + 1 === totalChunks) {
            process.stdout.write(`    > Processing chunk ${i + 1}/${totalChunks}...\r`);
        }
        const bulkOps = chunk.map(indicator => ({
          updateOne: {
            filter: { indicator, type: source.type },
            update: { $setOnInsert: { indicator, type: source.type, firstSeen: new Date(), lastUpdated: new Date(), status: 'malicious' } },
            upsert: true
          }
        }));
        const result = await ThreatIndicatorModel.bulkWrite(bulkOps, { ordered: false });
        storedCount += result.upsertedCount;
        if (global.gc) { global.gc(); }
      } catch (error) {
        // Silent error
      }
    }
    process.stdout.write("\n"); // Add a new line after the progress indicator is done
    return storedCount;
  }

  async analyzeWithMISP(source) {
    const connection = this.connections.get(source.type);
    const ThreatIndicatorModel = require('./models/ThreatIndicator')(connection);
    const MispScanResultModel = require('./models/MispScanResult')(connection);
    const unscanned = await ThreatIndicatorModel.find({ mispScanned: { $ne: true } }).select('indicator -_id').lean();
    if (unscanned.length === 0) return 0;

    const indicators = unscanned.map(doc => doc.indicator);
    const batchSize = source.batchSize;
    const totalBatches = Math.ceil(indicators.length / batchSize);
    let analyzedCount = 0;
    const scriptPath = path.join(__dirname, "misp_universal_scanner.py");
    
    for (let i = 0; i < totalBatches; i++) {
      const batch = indicators.slice(i * batchSize, (i + 1) * batchSize);
      try {
        if ((i + 1) % 10 === 0 || i + 1 === totalBatches) {
            process.stdout.write(`  - MISP Progress for ${source.type.toUpperCase()}: Batch ${i + 1}/${totalBatches}...\r`);
        }
        const results = await this.runMispScan(scriptPath, batch);
        if (results && results.length > 0) {
          const bulkOps = results.map(result => ({
            updateOne: {
              filter: { indicator: result.indicator, type: source.type },
              update: { $set: { ...result, scannedAt: new Date() } },
              upsert: true
            }
          }));
          await MispScanResultModel.bulkWrite(bulkOps, { ordered: false });
          await ThreatIndicatorModel.updateMany({ indicator: { $in: batch } }, { $set: { mispScanned: true, lastMispScan: new Date() } });
          analyzedCount += batch.length;
        }
        await this.delay(1000);
      } catch (error) {
        // Silent error
      }
    }
    return analyzedCount;
  }

  async runMispScan(scriptPath, indicators) {
    return new Promise((resolve, reject) => {
      const pythonProcess = spawn("python3", [scriptPath, ...indicators]);
      let scriptOutput = "";
      let errorOutput = "";
      pythonProcess.stdout.on("data", (data) => { scriptOutput += data.toString(); });
      pythonProcess.stderr.on("data", (data) => { errorOutput += data.toString(); });
      pythonProcess.on("close", (code) => {
        if (code !== 0) return reject(new Error(`MISP scan failed`));
        try {
          resolve(JSON.parse(scriptOutput));
        } catch (error) {
          reject(new Error(`Error parsing Python output`));
        }
      });
      setTimeout(() => { pythonProcess.kill(); reject(new Error("MISP scan timed out")); }, 300000);
    });
  }

  // --- Validator Functions ---
  isValidIP(ip) { return /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/.test(ip); }
  isValidSHA256(hash) { return /^[a-fA-F0-9]{64}$/.test(hash); }
  isValidMD5(hash) { return /^[a-fA-F0-9]{32}$/.test(hash); }
  isValidHostname(hostname) { return /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/.test(hostname); }
  isValidDomain(domain) { return this.isValidHostname(domain); }
  detectIndicatorType(indicator) {
    if (this.isValidIP(indicator)) return 'ip';
    if (this.isValidSHA256(indicator)) return 'sha256';
    if (this.isValidMD5(indicator)) return 'md5';
    if (this.isValidDomain(indicator)) return 'domain'; // Domain check covers hostname
    return null;
  }

  setupExpress() {
    this.expressApp.set("view engine", "ejs");
    this.expressApp.set("views", path.join(__dirname, "views"));

    this.expressApp.get("/", async (req, res) => {
        const stats = await this.getDashboardStats();
        res.render("threat-intelligence", { stats, scanResult: null, error: null, processingStatus: this.isProcessing, lastRunStats: this.processingStats });
    });

    this.expressApp.post("/scan", async (req, res) => {
        const { indicator } = req.body;
        let scanResult = null;
        let error = null;
        const indicatorType = this.detectIndicatorType(indicator);

        if (!indicatorType) {
            error = "Invalid or unsupported indicator type.";
        } else {
            try {
                const connection = this.connections.get(indicatorType);
                const ThreatIndicatorModel = require('./models/ThreatIndicator')(connection);
                const MispScanResultModel = require('./models/MispScanResult')(connection);

                const threatIndicator = await ThreatIndicatorModel.findOne({ indicator }).lean();
                const mispResult = await MispScanResultModel.findOne({ indicator }).lean();

                if (threatIndicator) {
                    const combinedData = { ...threatIndicator, ...mispResult };
                    scanResult = { indicator, type: indicatorType, source: 'Local Database', data: combinedData };
                } else if (this.isProcessing) {
                    scanResult = { 
                        indicator, 
                        type: indicatorType, 
                        source: 'Local Database Only', 
                        data: { message: "Indicator not found in local DB. Live MISP scan is disabled during bulk processing." } 
                    };
                } else {
                    const scriptPath = path.join(__dirname, "misp_universal_scanner.py");
                    const mispResults = await this.runMispScan(scriptPath, [indicator]);
                    if (mispResults && mispResults.length > 0) {
                        scanResult = { indicator, type: indicatorType, source: 'Live MISP Scan', data: mispResults[0] };
                    } else {
                        scanResult = { indicator, type: indicatorType, source: 'Live MISP Scan', data: { message: "Not found in MISP." } };
                    }
                }
            } catch (e) {
                error = "An error occurred during the scan. Check MISP configuration and connectivity.";
            }
        }
        const stats = await this.getDashboardStats();
        res.render("threat-intelligence", { stats, scanResult, error, processingStatus: this.isProcessing, lastRunStats: this.processingStats });
    });
    
    this.expressApp.post("/api/process/manual", (req, res) => {
        if (this.isProcessing) {
            return res.status(409).json({ message: "Processing already in progress" });
        }
        this.processAllSources().catch(console.error); // Run in background
        res.redirect('/');
    });

    const PORT = process.env.PORT || 3001;
    this.expressApp.listen(PORT, () => {
      console.log(`\n🌐 Web server running at http://localhost:${PORT}`);
    });
  }

  async getDashboardStats() {
      const stats = {};
      for (const source of this.dataSources) {
          const connection = this.connections.get(source.type);
          const ThreatIndicatorModel = require('./models/ThreatIndicator')(connection);
          const MispScanResultModel = require('./models/MispScanResult')(connection);
          const totalCount = await ThreatIndicatorModel.countDocuments();
          const scannedCount = await MispScanResultModel.countDocuments();
          stats[source.type] = { total: totalCount, scanned: scannedCount };
      }
      return stats;
  }

  async showInitialStats() {
    console.log("\n" + "�".repeat(20));
    console.log("📊 CURRENT DATABASE STATISTICS");
    console.log("📊".repeat(20));
    const stats = await this.getDashboardStats();
    for(const type in stats){
        console.log(`🗄️  ${type.toUpperCase()} indicators: ${stats[type].total.toLocaleString()}`);
        console.log(`🛡️  ${type.toUpperCase()} MISP scanned: ${stats[type].scanned.toLocaleString()}`);
    }
    console.log("📊".repeat(20) + "\n");
  }

  setupCLI() {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.on("line", async (input) => {
      const command = input.trim().toLowerCase();
      switch (command) {
        case "r":
        case "process":
          console.log("\n🔧 Running manual processing...");
          if (!this.isProcessing) { this.processAllSources().catch(console.error); } 
          else { console.log("⚠️ Processing already in progress"); }
          break;
        case "s":
          console.log(`\n📊 Processing Status: ${this.isProcessing ? "🟢 Running" : "🔴 Idle"}`);
          break;
        case "d":
          await this.showInitialStats();
          break;
        case "q":
          console.log("👋 Shutting down application...");
          process.exit(0);
          break;
        default:
          console.log("❓ Unknown command. Available: r, s, d, process, q");
      }
    });
  }

  setupGracefulShutdown() {
    const gracefulShutdown = async (signal) => {
      console.log(`\n🛑 Received ${signal}. Shutting down gracefully...`);
      for (const [type, connection] of this.connections) {
        await connection.close();
        console.log(`✅ Closed ${type} database connection`);
      }
      process.exit(0);
    };
    process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
    process.on("SIGINT", () => gracefulShutdown("SIGINT"));
  }

  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

const app = new ThreatIntelligenceApp();
app.initialize().catch(console.error);
