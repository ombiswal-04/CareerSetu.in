const mongoose = require('mongoose');

const applicationSchema = mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    jobId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Job',
        required: true
    },
    status: {
        type: String,
        enum: ['applied', 'interview', 'rejected', 'accepted'],
        default: 'applied'
    },
    interviewDate: {
        type: String, // Storing as string or Date as preferred, using String for simplicity with Date picker
        default: null
    },
    interviewTime: {
        type: String,
        default: null
    },
    appliedAt: {
        type: Date,
        default: Date.now
    }
}, {
    timestamps: true
});

const Application = mongoose.model('Application', applicationSchema);
module.exports = Application;
