// Jobs [id] route - PUT and DELETE operations
export async function PUT(request, { params }) {
    try {
        const dns = await import('dns');
        if (dns.setDefaultResultOrder) dns.setDefaultResultOrder('ipv4first');
        dns.setServers(['8.8.8.8', '8.8.4.4']);

        const mongoose = (await import('mongoose')).default;
        const jwt = (await import('jsonwebtoken')).default;

        const MONGODB_URI = process.env.MONGO_URI;
        if (mongoose.connection.readyState === 0) {
            await mongoose.connect(MONGODB_URI, { bufferCommands: false, serverSelectionTimeoutMS: 30000 });
        }

        // Verify admin
        const authHeader = request.headers.get('authorization');
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return Response.json({ message: 'Not authorized' }, { status: 401 });
        }
        const token = authHeader.split(' ')[1];
        let decoded;
        try { decoded = jwt.verify(token, process.env.JWT_SECRET); }
        catch { return Response.json({ message: 'Token failed' }, { status: 401 }); }

        const bcrypt = (await import('bcryptjs')).default;
        let User = mongoose.models.User || mongoose.model('User', new mongoose.Schema({
            name: { type: String, required: true },
            email: { type: String, required: true, unique: true },
            password: { type: String, required: true },
            role: { type: String, enum: ['user', 'admin'], default: 'user' },
            resumeUrl: { type: String, default: null }
        }, { timestamps: true }));

        const user = await User.findById(decoded.id).select('-password');
        if (!user || user.role !== 'admin') {
            return Response.json({ message: 'Not authorized as admin' }, { status: 401 });
        }

        let Job = mongoose.models.Job || mongoose.model('Job', new mongoose.Schema({
            title: { type: String, required: true },
            company: { type: String, required: true },
            location: { type: String, required: true },
            salary: { type: String, required: true },
            jobType: { type: String, required: true },
            description: { type: String, required: true },
            source: { type: String, enum: ['Admin', 'CareerSetu', 'LinkedIn', 'Indeed', 'Naukri', 'Unstop', 'External'], default: 'CareerSetu' },
            applyUrl: { type: String, required: false },
            createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }
        }, { timestamps: true }));

        const { id } = await params;
        const body = await request.json();
        const job = await Job.findByIdAndUpdate(id, body, { new: true });

        if (!job) return Response.json({ message: 'Job not found' }, { status: 404 });
        return Response.json(job);
    } catch (error) {
        console.error('Update job error:', error);
        return Response.json({ message: error.message }, { status: 500 });
    }
}

export async function DELETE(request, { params }) {
    try {
        const dns = await import('dns');
        if (dns.setDefaultResultOrder) dns.setDefaultResultOrder('ipv4first');
        dns.setServers(['8.8.8.8', '8.8.4.4']);

        const mongoose = (await import('mongoose')).default;
        const jwt = (await import('jsonwebtoken')).default;

        const MONGODB_URI = process.env.MONGO_URI;
        if (mongoose.connection.readyState === 0) {
            await mongoose.connect(MONGODB_URI, { bufferCommands: false, serverSelectionTimeoutMS: 30000 });
        }

        const authHeader = request.headers.get('authorization');
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return Response.json({ message: 'Not authorized' }, { status: 401 });
        }
        const token = authHeader.split(' ')[1];
        let decoded;
        try { decoded = jwt.verify(token, process.env.JWT_SECRET); }
        catch { return Response.json({ message: 'Token failed' }, { status: 401 }); }

        let User = mongoose.models.User || mongoose.model('User', new mongoose.Schema({
            name: { type: String, required: true },
            email: { type: String, required: true, unique: true },
            password: { type: String, required: true },
            role: { type: String, enum: ['user', 'admin'], default: 'user' },
            resumeUrl: { type: String, default: null }
        }, { timestamps: true }));

        const user = await User.findById(decoded.id).select('-password');
        if (!user || user.role !== 'admin') {
            return Response.json({ message: 'Not authorized as admin' }, { status: 401 });
        }

        let Job = mongoose.models.Job || mongoose.model('Job', new mongoose.Schema({
            title: { type: String, required: true },
            company: { type: String, required: true },
            location: { type: String, required: true },
            salary: { type: String, required: true },
            jobType: { type: String, required: true },
            description: { type: String, required: true },
            source: { type: String, enum: ['Admin', 'CareerSetu', 'LinkedIn', 'Indeed', 'Naukri', 'Unstop', 'External'], default: 'CareerSetu' },
            applyUrl: { type: String, required: false },
            createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }
        }, { timestamps: true }));

        const { id } = await params;
        const job = await Job.findByIdAndDelete(id);

        if (!job) return Response.json({ message: 'Job not found' }, { status: 404 });
        return Response.json({ message: 'Job deleted' });
    } catch (error) {
        console.error('Delete job error:', error);
        return Response.json({ message: error.message }, { status: 500 });
    }
}
