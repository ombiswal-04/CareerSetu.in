const mongoose = require('mongoose');

const jobSchema = mongoose.Schema({
    title: {
        type: String,
        required: true
    },
    company: {
        type: String,
        required: true
    },
    location: {
        type: String,
        required: true
    },
    salary: {
        type: String,
        required: true
    },
    jobType: {
        type: String,
        required: true // e.g., Full-time, Part-time
    },
    description: {
        type: String,
        required: true
    },
    source: {
        type: String,
        enum: ['Admin', 'CareerSetu', 'LinkedIn', 'Indeed', 'Naukri', 'Unstop', 'External'],
        default: 'CareerSetu'
    },
    applyUrl: {
        type: String,
        required: false // Only required for external jobs
    },
    createdBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    }
}, {
    timestamps: true
});

const Job = mongoose.model('Job', jobSchema);
module.exports = Job;
