const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const schema = new Schema({
    name: String,
    status: Boolean,
    modified: Date
});

schema.virtual('isActive').get(function () {
    return this.status;
});

module.exports = mongoose.model('Utilities', schema);