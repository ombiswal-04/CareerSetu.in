// GET /api/jobs - Get all jobs (Public)
export async function GET() {
    try {
        // Step 1: Configure DNS FIRST (before any mongoose imports)
        const dns = await import('dns');
        if (dns.setDefaultResultOrder) {
            dns.setDefaultResultOrder('ipv4first');
        }
        dns.setServers(['8.8.8.8', '8.8.4.4']);

        // Step 2: Import mongoose AFTER DNS config
        const mongoose = (await import('mongoose')).default;

        // Step 3: Connect to MongoDB
        const MONGODB_URI = process.env.MONGO_URI;
        if (!MONGODB_URI) {
            return Response.json({ message: 'MONGO_URI not found' }, { status: 500 });
        }

        if (mongoose.connection.readyState === 0) {
            await mongoose.connect(MONGODB_URI, {
                bufferCommands: false,
                serverSelectionTimeoutMS: 30000,
            });
        }

        // Step 4: Define or get Job model
        let Job;
        if (mongoose.models.Job) {
            Job = mongoose.models.Job;
        } else {
            const jobSchema = new mongoose.Schema({
                title: { type: String, required: true },
                company: { type: String, required: true },
                location: { type: String, required: true },
                salary: { type: String, required: true },
                jobType: { type: String, required: true },
                description: { type: String, required: true },
                source: { type: String, enum: ['Admin', 'CareerSetu', 'LinkedIn', 'Indeed', 'Naukri', 'Unstop', 'External'], default: 'CareerSetu' },
                applyUrl: { type: String, required: false },
                createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }
            }, { timestamps: true });
            Job = mongoose.model('Job', jobSchema);
        }

        // Step 5: Query jobs
        const jobs = await Job.find({});
        return Response.json(jobs);
    } catch (error) {
        console.error('Get jobs error:', error);
        return Response.json({ message: error.message }, { status: 500 });
    }
}

// POST /api/jobs - Create a job (Admin only)
export async function POST(request) {
    try {
        // Step 1: Configure DNS FIRST
        const dns = await import('dns');
        if (dns.setDefaultResultOrder) {
            dns.setDefaultResultOrder('ipv4first');
        }
        dns.setServers(['8.8.8.8', '8.8.4.4']);

        // Step 2: Import mongoose and jwt AFTER DNS config
        const mongoose = (await import('mongoose')).default;
        const jwt = (await import('jsonwebtoken')).default;

        // Step 3: Connect to MongoDB
        const MONGODB_URI = process.env.MONGO_URI;
        if (mongoose.connection.readyState === 0) {
            await mongoose.connect(MONGODB_URI, {
                bufferCommands: false,
                serverSelectionTimeoutMS: 30000,
            });
        }

        // Step 4: Verify user is admin
        const authHeader = request.headers.get('authorization');
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return Response.json({ message: 'Not authorized' }, { status: 401 });
        }

        const token = authHeader.split(' ')[1];
        let decoded;
        try {
            decoded = jwt.verify(token, process.env.JWT_SECRET);
        } catch (e) {
            return Response.json({ message: 'Not authorized, token failed' }, { status: 401 });
        }

        // Get User model
        let User;
        if (mongoose.models.User) {
            User = mongoose.models.User;
        } else {
            const bcrypt = (await import('bcryptjs')).default;
            const userSchema = new mongoose.Schema({
                name: { type: String, required: true },
                email: { type: String, required: true, unique: true },
                password: { type: String, required: true },
                role: { type: String, enum: ['user', 'admin'], default: 'user' },
                resumeUrl: { type: String, default: null }
            }, { timestamps: true });
            userSchema.methods.matchPassword = async function (p) { return await bcrypt.compare(p, this.password); };
            userSchema.pre('save', async function () { if (!this.isModified('password')) return; this.password = await bcrypt.hash(this.password, 10); });
            User = mongoose.model('User', userSchema);
        }

        const user = await User.findById(decoded.id).select('-password');
        if (!user || user.role !== 'admin') {
            return Response.json({ message: 'Not authorized as admin' }, { status: 401 });
        }

        // Step 5: Get Job model and create job
        let Job;
        if (mongoose.models.Job) {
            Job = mongoose.models.Job;
        } else {
            const jobSchema = new mongoose.Schema({
                title: { type: String, required: true },
                company: { type: String, required: true },
                location: { type: String, required: true },
                salary: { type: String, required: true },
                jobType: { type: String, required: true },
                description: { type: String, required: true },
                source: { type: String, enum: ['Admin', 'CareerSetu', 'LinkedIn', 'Indeed', 'Naukri', 'Unstop', 'External'], default: 'CareerSetu' },
                applyUrl: { type: String, required: false },
                createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }
            }, { timestamps: true });
            Job = mongoose.model('Job', jobSchema);
        }

        const body = await request.json();
        const job = new Job({
            title: body.title,
            company: body.company,
            location: body.location,
            salary: body.salary,
            jobType: body.jobType,
            description: body.description,
            source: body.source || 'CareerSetu',
            applyUrl: body.applyUrl,
            createdBy: user._id
        });

        const createdJob = await job.save();
        return Response.json(createdJob, { status: 201 });
    } catch (error) {
        console.error('Create job error:', error);
        return Response.json({ message: error.message }, { status: 500 });
    }
}
