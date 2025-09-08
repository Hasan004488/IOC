const express = require("express");
const path = require("path");
const fs = require("fs");
const { MongoClient } = require("mongodb");
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
    this.dbClient = null;
    this.dbs = new Map();
    this.processingStats = { lastRun: null, details: {} };
    this.cachedSummaryStats = { domain: 0, ip: 0, hashes: 0 };
    this.cachedDashboardStats = {};
  }

  async initialize() {
    try {
      console.log("🚀 Initializing Application...");
      await this.initializeDatabaseConnection();
      await this.ensureIndexes();
      this.setupExpress();
      await this.updateCachedStats();
      this.setupScheduler();
      this.setupCLI();
      this.setupGracefulShutdown();
      console.log("✅ Application initialized successfully!");
      console.log(
        "📋 Available commands: r (or process), import-misp, scan-misp, s, d, q"
      );
    } catch (error) {
      console.error(
        "❌ Failed to initialize application:",
        error.message,
        error.stack
      );
      process.exit(1);
    }
  }

  async initializeDatabaseConnection() {
    const client = new MongoClient(process.env.MONGODB_URI, {
      maxPoolSize: 20,
      serverSelectionTimeoutMS: 10000,
      socketTimeoutMS: 60000,
      appName: "ThreatIntelApp",
    });
    await client.connect();
    this.dbClient = client;
    console.log("✅ Connected successfully to MongoDB server");

    this.dataSources.push({ type: "misp", dbName: "mispDB" });
    for (const source of this.dataSources) {
      this.dbs.set(source.type, this.dbClient.db(source.dbName));
    }
    console.log("✅ Database handles obtained for all sources.");
  }

  async ensureIndexes() {
    console.log("🔍 Ensuring database indexes are up-to-date...");
    try {
      const mispAttributesCollection = this.dbs
        .get("misp")
        .collection("mispattributes");
      await mispAttributesCollection.createIndex(
        { value: 1 },
        { name: "value_idx" }
      );
      await mispAttributesCollection.createIndex(
        { uuid: 1 },
        { unique: true, name: "uuid_unique_idx" }
      );

      const threatSources = this.dataSources.filter(
        (s) => s.type !== "misp" && s.url
      );
      for (const source of threatSources) {
        const collection = this.dbs
          .get(source.type)
          .collection("threatindicators");
        await collection.createIndex(
          { indicator: 1, type: 1 },
          { unique: true, name: "indicator_type_unique_idx" }
        );
        await collection.createIndex(
          { mispScanned: 1 },
          { name: "mispScanned_idx" }
        );
      }
      console.log("✅ All database indexes verified.");
    } catch (error) {
      console.error("❌ Error ensuring indexes:", error.message);
    }
  }

  async updateCachedStats() {
    console.log("\n🔄 Updating cached database statistics...");
    const dashboardStats = {};
    const threatSources = this.dataSources.filter(
      (s) => s.type !== "misp" && s.url
    );

    for (const source of threatSources) {
      const collection = this.dbs
        .get(source.type)
        .collection("threatindicators");
      const totalCount = await collection.countDocuments();
      dashboardStats[source.type] = { total: totalCount };
    }
    this.cachedDashboardStats = dashboardStats;
    console.log("✅ Cached statistics updated successfully.");
    await this.showInitialStats();
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
    console.log(
      "⏰ Cron scheduler initialized for daily data fetching at midnight (Asia/Dhaka)."
    );
  }

  async importMispData() {
    if (this.isProcessing) {
      console.log("⚠️ A process is already running, please wait.");
      return;
    }
    const filePath = path.join(__dirname, "misp_output.json");
    if (!fs.existsSync(filePath)) {
      console.error(`\n❌ MISP data file not found at ${filePath}`);
      return;
    }
    this.isProcessing = true;
    console.log(`\n📦 Importing MISP data from ${filePath}...`);
    const mispAttributesCollection = this.dbs
      .get("misp")
      .collection("mispattributes");
    let totalUpserted = 0,
      totalModified = 0;
    try {
      const attributes = JSON.parse(fs.readFileSync(filePath, "utf-8"))
        ?.response?.Attribute;
      if (!attributes || attributes.length === 0) {
        console.log("   No attributes found in the MISP data file.");
        this.isProcessing = false;
        return;
      }
      console.log(
        `   Found ${attributes.length.toLocaleString()} attributes. Storing in database...`
      );
      const chunkSize = 5000;
      for (let i = 0; i < attributes.length; i += chunkSize) {
        process.stdout.write(
          `    > Processing chunk ${i / chunkSize + 1} of ${Math.ceil(
            attributes.length / chunkSize
          )}...\r`
        );
        const chunk = attributes.slice(i, i + chunkSize);
        const bulkOps = chunk.map((attr) => ({
          updateOne: {
            filter: { uuid: attr.uuid },
            update: { $set: attr },
            upsert: true,
          },
        }));
        if (bulkOps.length > 0) {
          const result = await mispAttributesCollection.bulkWrite(bulkOps, {
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
    const threatSources = this.dataSources.filter(
      (s) => s.type !== "misp" && s.url
    );
    const startTime = Date.now();
    try {
      console.log(
        "\n" +
          "🔄".repeat(20) +
          "\n🔄 FETCHING & STORING INDICATORS\n" +
          "🔄".repeat(20)
      );
      for (const source of threatSources) {
        await this.processSource(source);
      }
      const duration = ((Date.now() - startTime) / 1000 / 60).toFixed(2);
      console.log(
        "\n" +
          "✅".repeat(20) +
          "\n✅ DATA FETCHING COMPLETED\n" +
          "✅".repeat(20)
      );
      console.log(`⏱️  Total duration: ${duration} minutes`);
    } catch (error) {
      console.error("💥 Critical error during processing:", error.message);
    } finally {
      this.isProcessing = false;
      await this.updateCachedStats();
      console.log("\n✨ Automatically triggering MISP scan after data fetch.");
      await this.scanIndicatorsAgainstMisp();
    }
  }

  async processSource(source) {
    try {
      console.log(`\n📥 Fetching from ${source.type.toUpperCase()}...`);
      const indicators = await this.fetchIndicators(source);
      if (indicators.length === 0) {
        console.log(`  - No new indicators found.`);
        return;
      }
      console.log(
        `  - Fetched ${indicators.length.toLocaleString()} unique indicators.`
      );
      await this.storeIndicators(source, indicators);
    } catch (error) {
      console.error(
        `❌ Error processing source ${source.type}:`,
        error.message
      );
    }
  }

  async fetchIndicators(source) {
    try {
      const response = await axios.get(source.url, {
        timeout: 60000,
        responseType: "text",
      });
      if (response.status !== 200) throw new Error(`HTTP ${response.status}`);
      const rawData = response.data
        .split("\n")
        .map((l) => l.trim())
        .filter(Boolean)
        .filter((l) => !l.startsWith("#"));
      return [...new Set(rawData)].filter((indicator) =>
        source.validator(indicator)
      );
    } catch (error) {
      console.error(`  - Failed to fetch from ${source.url}: ${error.message}`);
      return [];
    }
  }

  async storeIndicators(source, indicators) {
    const collection = this.dbs.get(source.type).collection("threatindicators");
    let storedCount = 0;
    const chunkSize = source.chunkSize;
    console.log(
      `  - Storing ${indicators.length.toLocaleString()} indicators in chunks of ${chunkSize}...`
    );
    for (let i = 0; i < indicators.length; i += chunkSize) {
      const chunk = indicators.slice(i, i + chunkSize);
      const docs = chunk.map((indicator) => ({
        indicator,
        type: source.type,
        mispScanned: false,
        createdAt: new Date(),
        lastUpdated: new Date(),
      }));
      try {
        await collection.insertMany(docs, { ordered: false });
        storedCount += docs.length;
      } catch (error) {
        if (error.code === 11000 && error.result) {
          storedCount += error.result.nInserted;
        } else {
          // Ignore duplicate key errors, which are expected
        }
      }
      if (global.gc) global.gc();
    }
    console.log(
      `  - Stored ${storedCount.toLocaleString()} new indicators. Skipped ${
        indicators.length - storedCount
      } duplicates.`
    );
  }

  async scanIndicatorsAgainstMisp() {
    if (this.isProcessing) {
      console.log("⚠️ A process is already running, skipping MISP scan.");
      return;
    }
    this.isProcessing = true;
    console.log(
      "\n" +
        "🔍".repeat(20) +
        "\n🔍 SCANNING INDICATORS AGAINST MISP DB\n" +
        "🔍".repeat(20)
    );
    const startTime = Date.now();
    const mispAttributesCollection = this.dbs
      .get("misp")
      .collection("mispattributes");
    let totalScanned = 0,
      totalMatched = 0;

    try {
      const threatSources = this.dataSources.filter(
        (s) => s.type !== "misp" && s.url
      );
      for (const source of threatSources) {
        const collection = this.dbs
          .get(source.type)
          .collection("threatindicators");
        const indicatorsToScan = await collection
          .find(
            { mispScanned: false },
            { projection: { indicator: 1, _id: 0 } }
          )
          .toArray();
        if (indicatorsToScan.length === 0) continue;

        const values = indicatorsToScan.map((i) => i.indicator);
        console.log(
          `  - Scanning ${values.length.toLocaleString()} new '${
            source.type
          }' indicators...`
        );

        const matchedValues = new Set();
        const cursor = mispAttributesCollection.find(
          { value: { $in: values } },
          { projection: { value: 1 } }
        );
        for await (const doc of cursor) {
          matchedValues.add(doc.value);
        }

        if (matchedValues.size > 0) {
          await collection.updateMany(
            { indicator: { $in: Array.from(matchedValues) } },
            {
              $set: {
                status: "malicious-misp",
                mispScanned: true,
                lastMispScan: new Date(),
              },
            }
          );
        }
        await collection.updateMany(
          { indicator: { $in: values } },
          { $set: { mispScanned: true, lastMispScan: new Date() } }
        );
        totalScanned += values.length;
        totalMatched += matchedValues.size;
      }
    } catch (e) {
      console.error("❌ Error during MISP scan:", e.message);
    } finally {
      const duration = ((Date.now() - startTime) / 1000).toFixed(2);
      console.log(
        "\n" + "✅".repeat(20) + "\n✅ MISP SCAN COMPLETED\n" + "✅".repeat(20)
      );
      console.log(
        `   - Total Scanned: ${totalScanned.toLocaleString()}, Matches Found: ${totalMatched.toLocaleString()}`
      );
      console.log(`   - Duration: ${duration} seconds`);
      this.isProcessing = false;
    }
  }

  isValidIP = (ip) =>
    /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/.test(
      ip
    );
  isValidSHA256 = (hash) => /^[a-fA-F0-9]{64}$/.test(hash);
  isValidMD5 = (hash) => /^[a-fA-F0-9]{32}$/.test(hash);
  isValidHostname = (hostname) =>
    /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/.test(
      hostname
    );
  isValidDomain = (domain) => this.isValidHostname(domain);

  detectIndicatorType(indicator) {
    if (this.isValidIP(indicator)) return "ip";
    if (this.isValidSHA256(indicator)) return "sha256";
    if (this.isValidMD5(indicator)) return "md5";
    if (this.isValidHostname(indicator)) return "domain"; // Domain is a more general term
    return null;
  }

  setupExpress() {
    this.expressApp.set("view engine", "ejs");
    this.expressApp.set("views", path.join(__dirname, "views"));

    this.expressApp.get("/", async (req, res) => {
      res.render("index", {
        dashboardStats: this.cachedDashboardStats,
        scanResult: null,
      });
    });

    this.expressApp.post("/scan", async (req, res) => {
      const indicator = req.body.indicator.trim();
      let scanResult = { indicator, source: "Not Found", data: {} };
      try {
        const indicatorType = this.detectIndicatorType(indicator);
        if (!indicatorType) {
          scanResult = {
            indicator,
            source: "Invalid",
            data: { message: "Invalid format." },
          };
        } else {
          const mispData = await this.dbs
            .get("misp")
            .collection("mispattributes")
            .find({ value: indicator })
            .toArray();
          if (mispData.length > 0) {
            scanResult = { indicator, source: "MISP Database", data: mispData };
          } else {
            const threatIndicator = await this.dbs
              .get(indicatorType)
              .collection("threatindicators")
              .findOne({ indicator });
            if (threatIndicator) {
              scanResult = {
                indicator,
                source: "Local Threat Feed",
                data: threatIndicator,
              };
            }
          }
        }
      } catch (e) {
        console.error("Scan error:", e.message);
        scanResult = {
          indicator,
          source: "Error",
          data: { message: "An error occurred during scan." },
        };
      }
      res.render("index", {
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
    console.log(
      "\n" +
        "📊".repeat(20) +
        "\n📊 CURRENT DATABASE STATISTICS\n" +
        "📊".repeat(20)
    );
    for (const type in this.cachedDashboardStats) {
      console.log(
        `🗄️  ${type.toUpperCase()} indicators: ${this.cachedDashboardStats[
          type
        ].total.toLocaleString()}`
      );
    }
    const mispCount = await this.dbs
      .get("misp")
      .collection("mispattributes")
      .countDocuments();
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
          await this.processAllSources();
          break;
        case "import-misp":
          await this.importMispData();
          break;
        case "scan-misp":
          await this.scanIndicatorsAgainstMisp();
          break;
        case "s":
          console.log(
            `\n📊 Processing Status: ${
              this.isProcessing ? "🟢 Running" : "🔴 Idle"
            }`
          );
          break;
        case "d":
          await this.updateCachedStats();
          break;
        case "q":
          await this.setupGracefulShutdown("CLI exit");
          break;
        default:
          console.log(
            "❓ Unknown command. Available: r, import-misp, scan-misp, s, d, q"
          );
      }
    });
  }

  async setupGracefulShutdown(signal) {
    console.log(`\n🛑 Received ${signal}. Shutting down gracefully...`);
    if (this.dbClient) {
      await this.dbClient.close();
      console.log("   - MongoDB connection closed.");
    }
    process.exit(0);
  }
}

const app = new ThreatIntelligenceApp();
app.initialize();

process.on("SIGTERM", () => app.setupGracefulShutdown("SIGTERM"));
process.on("SIGINT", () => app.setupGracefulShutdown("SIGINT"));
