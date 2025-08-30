const mongoose = require('mongoose');

// This model is now a function that accepts a connection
module.exports = (connection) => {
  if (connection.models.ThreatIndicator) {
    return connection.models.ThreatIndicator;
  }

  const threatIndicatorSchema = new mongoose.Schema({
    indicator: { type: String, required: true, trim: true },
    type: { type: String, required: true, enum: ['ip', 'sha256', 'md5', 'hostname', 'domain'] },
    status: { type: String, default: 'malicious', enum: ['malicious', 'suspicious', 'clean', 'unknown'] },
    firstSeen: { type: Date, default: Date.now },
    lastUpdated: { type: Date, default: Date.now },
    isActive: { type: Boolean, default: true },
    source: { type: String, default: 'threatwinds' },
    confidence: { type: Number, min: 0, max: 100, default: 75 },
    tags: [{ type: String, trim: true }],
    mispScanned: { type: Boolean, default: false },
    lastMispScan: { type: Date },
  }, { timestamps: true });

  threatIndicatorSchema.index({ indicator: 1, type: 1 }, { unique: true });
  threatIndicatorSchema.index({ type: 1, mispScanned: 1 });
  
  return connection.model('ThreatIndicator', threatIndicatorSchema);
};
