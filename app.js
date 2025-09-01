const express = require("express");
const path = require("path");
const fs = require("fs");
const mongoose = require("mongoose");
const readline = require("readline");
const cron = require("node-cron");
const axios = require("axios");
require("dotenv").config();

class ThreatIntelligenceApp {
  constructor() {
    this.expressApp = express();
    this.expressApp.use(express.json({ limit: "50mb" }));
    this.expressApp.use(express.urlencoded({ extended: true, limit: "50mb" }));
    this.expressApp.use(express.static(path.join(__dirname, "public")));

    this.dataSources = [
      {
        type: "ip",
        url: process.env.IP_FETCH_URL,
        dbName: "dw_ioc_ip",
        chunkSize: 15000,
        validator: this.isValidIP.bind(this),
      },
      {
        type: "sha256",
        url: process.env.SHA256_FETCH_URL,
        dbName: "dw_ioc_sha256",
        chunkSize: 15000,
        validator: this.isValidSHA256.bind(this),
      },
      {
        type: "md5",
        url: process.env.MD5_FETCH_URL,
        dbName: "dw_ioc_md5",
        chunkSize: 15000,
        validator: this.isValidMD5.bind(this),
      },
      {
        type: "hostname",
        url: process.env.HOSTNAME_FETCH_URL,
        dbName: "dw_ioc_hostname",
        chunkSize: 15000,
        validator: this.isValidHostname.bind(this),
      },
      {
        type: "domain",
        url: process.env.DOMAIN_FETCH_URL,
        dbName: "dw_ioc_domain",
        chunkSize: 15000,
        validator: this.isValidDomain.bind(this),
      },
    ];

    this.isProcessing = false;
    this.connections = new Map();
    this.processingStats = { lastRun: null, details: {} };
    this.cachedSummaryStats = { domain: 0, ip: 0, hashes: 0 };
    this.cachedDashboardStats = {};
  }

  async initialize() {
    try {
      console.log("🚀 Initializing Application...");
      await this.initializeDatabaseConnections();
      this.setupExpress();
      await this.updateCachedStats();
      this.setupScheduler();
      this.setupCLI();
      this.setupGracefulShutdown();
      console.log("✅ Application initialized successfully!");
      console.log(
        "📋 Available commands: r (or process), import-misp, s, d, q"
      );
    } catch (error) {
      console.error("❌ Failed to initialize application:", error.message);
      process.exit(1);
    }
  }

  async updateCachedStats() {
    console.log("\n🔄 Updating cached database statistics...");
    const summaryStats = { domain: 0, ip: 0, hashes: 0 };
    const dashboardStats = {};
    const threatSources = this.dataSources.filter(
      (s) => s.type !== "misp" && s.url
    );

    for (const source of threatSources) {
      const connection = this.connections.get(source.type);
      const ThreatIndicatorModel =
        require("./models/ThreatIndicator")(connection);
      const totalCount = await ThreatIndicatorModel.countDocuments();
      dashboardStats[source.type] = { total: totalCount };

      if (source.type === "domain" || source.type === "hostname") {
        summaryStats.domain += totalCount;
      } else if (source.type === "ip") {
        summaryStats.ip = totalCount;
      } else if (source.type === "md5" || source.type === "sha256") {
        summaryStats.hashes += totalCount;
      }
    }
    this.cachedSummaryStats = summaryStats;
    this.cachedDashboardStats = dashboardStats;
    console.log("✅ Cached statistics updated successfully.");
    await this.showInitialStats();
  }

  async initializeDatabaseConnections() {
    this.dataSources.push({ type: "misp", dbName: "mispDB" });
    for (const source of this.dataSources) {
      try {
        const connection = await mongoose.createConnection(
          process.env.MONGODB_URI.replace(/\/\w*$/, `/${source.dbName}`),
          {
            maxPoolSize: 15,
            serverSelectionTimeoutMS: 5000,
            socketTimeoutMS: 45000,
          }
        );
        this.connections.set(source.type, connection);
        console.log(`✅ Connected to ${source.dbName} database`);
      } catch (error) {
        console.error(
          `❌ Failed to connect to ${source.dbName} database:`,
          error.message
        );
        throw error;
      }
    }
  }

  setupScheduler() {
    cron.schedule(
      "0 0 * * *",
      async () => {
        console.log(
          "🕛 Midnight scheduler triggered - Starting daily processing..."
        );
        await this.processAllSources();
      },
      { timezone: "Asia/Dhaka" }
    );
    console.log("⏰ Cron scheduler initialized for daily data fetching");
  }

  async importMispData() {
    if (this.isProcessing) {
      console.log("⚠️ A process is already running, please wait.");
      return;
    }
    const filePath = path.join(__dirname, "misp_output.json");
    if (!fs.existsSync(filePath)) {
      console.error(`\n❌ MISP data file not found at ${filePath}`);
      console.log(
        "   Please run the curl command to download it before importing."
      );
      return;
    }
    this.isProcessing = true;
    console.log(`\n📦 Importing MISP data from ${filePath}...`);
    const mispConnection = this.connections.get("misp");
    const MispAttributeModel = require("./models/MispAttribute")(
      mispConnection
    );
    let totalUpserted = 0,
      totalModified = 0;
    try {
      const rawData = fs.readFileSync(filePath);
      const mispJson = JSON.parse(rawData);
      const attributes = mispJson?.response?.Attribute;
      if (!attributes || attributes.length === 0) {
        console.log("   No attributes found in the MISP data file.");
        this.isProcessing = false;
        return;
      }
      console.log(
        `   Found ${attributes.length.toLocaleString()} attributes. Storing in database...`
      );
      const chunkSize = 5000;
      const totalChunks = Math.ceil(attributes.length / chunkSize);
      for (let i = 0; i < totalChunks; i++) {
        process.stdout.write(
          `    > Processing chunk ${i + 1} of ${totalChunks}...\r`
        );
        const chunk = attributes.slice(i * chunkSize, (i + 1) * chunkSize);
        const bulkOps = chunk.map((attr) => ({
          updateOne: {
            filter: { uuid: attr.uuid },
            update: { $set: attr },
            upsert: true,
          },
        }));
        if (bulkOps.length > 0) {
          const result = await MispAttributeModel.bulkWrite(bulkOps, {
            ordered: false,
          });
          totalUpserted += result.upsertedCount;
          totalModified += result.modifiedCount;
        }
      }
      console.log("\n✅ MISP data import complete.                  ");
      console.log(`   - New records: ${totalUpserted.toLocaleString()}`);
      console.log(`   - Updated records: ${totalModified.toLocaleString()}`);
    } catch (e) {
      console.error("\n❌ Error during MISP data import:", e.message);
    } finally {
      this.isProcessing = false;
      await this.updateCachedStats();
    }
  }

  async processAllSources() {
    if (this.isProcessing) {
      console.log("⚠️ Processing already in progress, skipping...");
      return;
    }
    this.isProcessing = true;
    this.processingStats = { lastRun: new Date(), details: {} };
    const threatSources = this.dataSources.filter((s) => s.type !== "misp");
    threatSources.forEach((source) => {
      this.processingStats.details[source.type] = {
        fetched: 0,
        inserted: 0,
        duplicates: 0,
      };
    });
    const startTime = Date.now();
    try {
      console.log("\n" + "🔄".repeat(20));
      console.log("🔄 FETCHING & STORING INDICATORS FROM THREAT FEEDS");
      console.log("🔄".repeat(20));
      for (const source of threatSources) {
        try {
          console.log(`\n📥 Fetching from ${source.type.toUpperCase()}...`);
          const indicators = await this.fetchIndicators(source);
          if (indicators.length === 0) {
            console.log(`  - No new indicators found.`);
            continue;
          }
          this.processingStats.details[source.type].fetched = indicators.length;
          console.log(
            `  - Fetched ${indicators.length.toLocaleString()} unique indicators.`
          );
          const storedCount = await this.storeIndicators(source, indicators);
          this.processingStats.details[source.type].inserted = storedCount;
          this.processingStats.details[source.type].duplicates =
            indicators.length - storedCount;
          console.log(
            `  - Stored ${storedCount.toLocaleString()} new indicators.`
          );
        } catch (error) {
          console.error(
            `❌ Error during fetch/store for ${source.type}:`,
            error.message
          );
        }
      }
      const duration = ((Date.now() - startTime) / 1000 / 60).toFixed(2);
      console.log(
        "\n" +
          "✅".repeat(20) +
          "\n✅ DATA FETCHING COMPLETED" +
          "\n✅".repeat(20)
      );
      console.log(`⏱️ Total duration: ${duration} minutes`);
    } catch (error) {
      console.error("💥 Critical error during processing:", error.message);
    } finally {
      this.isProcessing = false;
      await this.updateCachedStats();
    }
  }

  async fetchIndicators(source) {
    try {
      const response = await axios.get(source.url, {
        timeout: 60000,
        headers: {
          "User-Agent": "ThreatIntel-Monitor/2.0",
          Accept: "text/plain",
        },
      });
      if (response.status !== 200)
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      const rawData = response.data
        .split("\n")
        .map((line) => line.trim())
        .filter((line) => line && !line.startsWith("#"))
        .filter((indicator) => source.validator(indicator));
      return [...new Set(rawData)];
    } catch (error) {
      return [];
    }
  }

  async storeIndicators(source, indicators) {
    const connection = this.connections.get(source.type);
    const ThreatIndicatorModel = require("./models/ThreatIndicator")(
      connection
    );
    let storedCount = 0;
    const chunkSize = source.chunkSize;
    const totalChunks = Math.ceil(indicators.length / chunkSize);
    console.log(
      `  - Storing ${indicators.length.toLocaleString()} indicators in ${totalChunks} chunks...`
    );
    for (let i = 0; i < totalChunks; i++) {
      const chunk = indicators.slice(i * chunkSize, (i + 1) * chunkSize);
      try {
        if ((i + 1) % 10 === 0 || i + 1 === totalChunks) {
          process.stdout.write(
            `    > Processing chunk ${i + 1}/${totalChunks}...\r`
          );
        }
        const docs = chunk.map((indicator) => ({
          indicator,
          type: source.type,
        }));
        const result = await ThreatIndicatorModel.insertMany(docs, {
          ordered: false,
        });
        storedCount += result.length;
        if (global.gc) {
          global.gc();
        }
      } catch (error) {
        if (error.code === 11000) {
          storedCount += error.result.nInserted;
        }
      }
    }
    process.stdout.write("\n");
    return storedCount;
  }

  isValidIP(ip) {
    return /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/.test(
      ip
    );
  }
  isValidSHA256(hash) {
    return /^[a-fA-F0-9]{64}$/.test(hash);
  }
  isValidMD5(hash) {
    return /^[a-fA-F0-9]{32}$/.test(hash);
  }
  isValidHostname(hostname) {
    return /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/.test(
      hostname
    );
  }
  isValidDomain(domain) {
    return this.isValidHostname(domain);
  }
  detectIndicatorType(indicator) {
    if (this.isValidIP(indicator)) return "ip";
    if (this.isValidSHA256(indicator)) return "sha256";
    if (this.isValidMD5(indicator)) return "md5";
    if (this.isValidDomain(indicator)) return "domain";
    return null;
  }

  setupExpress() {
    this.expressApp.set("view engine", "ejs");
    this.expressApp.set("views", path.join(__dirname, "views"));
    if (process.env.NODE_ENV !== "production") {
      this.expressApp.set("view cache", false);
    }

    this.expressApp.get("/", async (req, res) => {
      res.render("index", {
        summaryStats: this.cachedSummaryStats,
        dashboardStats: this.cachedDashboardStats,
        scanResult: null,
      });
    });

    this.expressApp.post("/scan", async (req, res) => {
      const indicator = req.body.indicator.trim();
      let scanResult = null;

      const indicatorType = this.detectIndicatorType(indicator);
      if (!indicatorType) {
        scanResult = {
          indicator,
          source: "Invalid",
          data: {
            message: "Invalid indicator format. Please enter a valid IP, Domain, or Hash.",
          },
        };
        return res.render("index", {
          summaryStats: this.cachedSummaryStats,
          dashboardStats: this.cachedDashboardStats,
          scanResult,
        });
      }

      try {
        const mispConnection = this.connections.get("misp");
        const MispAttributeModel = require("./models/MispAttribute")(
          mispConnection
        );
        const mispData = await MispAttributeModel.find({
          value: indicator,
        }).lean();

        if (mispData && mispData.length > 0) {
          scanResult = { indicator, source: "MISP Database", data: mispData };
        } else {
          const connection = this.connections.get(indicatorType);
          const ThreatIndicatorModel = require("./models/ThreatIndicator")(
            connection
          );
          const threatIndicator = await ThreatIndicatorModel.findOne({
            indicator,
          }).lean();
          if (threatIndicator) {
            scanResult = {
              indicator,
              source: "Local Threat Feed",
              data: threatIndicator,
            };
          }
        }
        if (!scanResult) {
          scanResult = {
            indicator,
            source: "Not Found",
            data: { message: `This indicator was not found in any database.` },
          };
        }
      } catch (e) {
        scanResult = {
          indicator,
          source: "Error",
          data: { message: "An error occurred during the scan." },
        };
      }
      res.render("index", {
        summaryStats: this.cachedSummaryStats,
        dashboardStats: this.cachedDashboardStats,
        scanResult,
      });
    });

    const PORT = process.env.PORT || 3001;
    this.expressApp.listen(PORT, () => {
      console.log(`\n🌐 Web server running at http://localhost:${PORT}`);
    });
  }

  async showInitialStats() {
    console.log("\n" + "📊".repeat(20));
    console.log("📊 CURRENT DATABASE STATISTICS");
    console.log("📊".repeat(20));
    for (const type in this.cachedDashboardStats) {
      console.log(
        `🗄️  ${type.toUpperCase()} indicators: ${this.cachedDashboardStats[
          type
        ].total.toLocaleString()}`
      );
    }
    const mispConnection = this.connections.get("misp");
    const MispAttributeModel = require("./models/MispAttribute")(
      mispConnection
    );
    const mispCount = await MispAttributeModel.countDocuments();
    console.log(`🛡️  MISP indicators: ${mispCount.toLocaleString()}`);
    console.log("📊".repeat(20) + "\n");
  }

  setupCLI() {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });
    rl.on("line", async (input) => {
      const command = input.trim().toLowerCase();
      switch (command) {
        case "r":
        case "process":
          console.log("\n🔧 Running manual data fetching...");
          this.processAllSources().catch(console.error);
          break;
        case "import-misp":
          console.log("\n📦 Starting MISP data import...");
          this.importMispData().catch(console.error);
          break;
        case "s":
          console.log(
            `\n📊 Processing Status: ${
              this.isProcessing ? "🟢 Running" : "🔴 Idle"
            }`
          );
          break;
        case "d":
          await this.showInitialStats();
          break;
        case "q":
          console.log("👋 Shutting down application...");
          process.exit(0);
          break;
        default:
          console.log(
            "❓ Unknown command. Available: r (process), import-misp, s, d, q"
          );
      }
    });
  }

  setupGracefulShutdown() {
    const gracefulShutdown = async (signal) => {
      console.log(`\n🛑 Received ${signal}. Shutting down gracefully...`);
      for (const [, connection] of this.connections) {
        await connection.close();
      }
      console.log("All database connections closed.");
      process.exit(0);
    };
    process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
    process.on("SIGINT", () => gracefulShutdown("SIGINT"));
  }
}

const app = new ThreatIntelligenceApp();
app.initialize().catch(console.error);