// Job model - uses factory function to avoid static mongoose import
let Job = null;

export async function getJobModel() {
    if (Job) return Job;

    // Dynamic import of mongoose to ensure DNS is configured first by connectDB
    const mongoose = (await import('mongoose')).default;

    // Check if model already exists (from previous requests)
    if (mongoose.models.Job) {
        Job = mongoose.models.Job;
        return Job;
    }

    const jobSchema = new mongoose.Schema({
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
            required: true
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
            required: false
        },
        createdBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User',
            required: true
        }
    }, {
        timestamps: true
    });

    Job = mongoose.model('Job', jobSchema);
    return Job;
}

// For backwards compatibility, export a getter function as default
export default { getJobModel };
