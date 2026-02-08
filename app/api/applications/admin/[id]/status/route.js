// Admin - Update application status route
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

        let Application = mongoose.models.Application || mongoose.model('Application', new mongoose.Schema({
            user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
            job: { type: mongoose.Schema.Types.ObjectId, ref: 'Job', required: true },
            status: { type: String, enum: ['applied', 'in-progress', 'interview scheduled', 'rejected', 'accepted'], default: 'applied' },
            interviewDate: { type: Date },
            interviewTime: { type: String },
            appliedAt: { type: Date, default: Date.now }
        }, { timestamps: true }));

        const user = await User.findById(decoded.id).select('-password');
        if (!user || user.role !== 'admin') {
            return Response.json({ message: 'Not authorized as admin' }, { status: 401 });
        }

        const { id } = await params;
        const { status } = await request.json();

        const application = await Application.findByIdAndUpdate(id, { status }, { new: true });
        if (!application) return Response.json({ message: 'Application not found' }, { status: 404 });

        return Response.json(application);
    } catch (error) {
        console.error('Update status error:', error);
        return Response.json({ message: error.message }, { status: 500 });
    }
}
