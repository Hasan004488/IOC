const mongoose = require('mongoose');

// This model is now a function that accepts a connection
module.exports = (connection) => {
    if (connection.models.MispScanResult) {
        return connection.models.MispScanResult;
    }

    const mispScanResultSchema = new mongoose.Schema({
        indicator: { type: String, required: true, trim: true },
        type: { type: String, required: true, enum: ['ip', 'sha256', 'md5', 'hostname', 'domain'] },
        scannedAt: { type: Date, default: Date.now },
        mispEventCount: { type: Number, default: 0 },
        threatLevel: { type: String, enum: ['low', 'medium', 'high', 'critical', 'unknown'], default: 'unknown' },
        malwareFamily: [String],
        attributes: { type: mongoose.Schema.Types.Mixed },
        rawResponse: { type: mongoose.Schema.Types.Mixed }
    }, { timestamps: true });

    mispScanResultSchema.index({ indicator: 1, type: 1 }, { unique: true });
    mispScanResultSchema.index({ scannedAt: -1 });

    return connection.model('MispScanResult', mispScanResultSchema);
};
