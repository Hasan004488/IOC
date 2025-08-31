const mongoose = require('mongoose');

// This model is for storing attributes from the MISP JSON dump.
// A flexible schema is used because MISP attributes can vary.
module.exports = (connection) => {
  if (connection.models.MispAttribute) {
    return connection.models.MispAttribute;
  }

  const mispAttributeSchema = new mongoose.Schema({
    // Using a flexible schema to capture all fields from the JSON file
  }, { strict: false, timestamps: true });

  // Index the 'value' field for fast lookups during scans
  mispAttributeSchema.index({ value: 1 });
  mispAttributeSchema.index({ uuid: 1 }, { unique: true });

  return connection.model('MispAttribute', mispAttributeSchema);
};