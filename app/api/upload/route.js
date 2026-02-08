import { writeFile, unlink, mkdir } from 'fs/promises';
import { join } from 'path';

// Upload resume route
export async function POST(request) {
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

        const user = await User.findById(decoded.id);
        if (!user) return Response.json({ message: 'User not found' }, { status: 404 });

        const formData = await request.formData();
        const file = formData.get('resume');

        if (!file) return Response.json({ message: 'No file uploaded' }, { status: 400 });
        if (!file.name.endsWith('.pdf')) {
            return Response.json({ message: 'Only PDF files are allowed' }, { status: 400 });
        }
        if (file.size > 5 * 1024 * 1024) {
            return Response.json({ message: 'File size must be less than 5MB' }, { status: 400 });
        }

        const bytes = await file.arrayBuffer();
        const buffer = Buffer.from(bytes);

        const uploadsDir = join(process.cwd(), 'public', 'uploads');
        await mkdir(uploadsDir, { recursive: true });

        const fileName = `resume-${user._id}-${Date.now()}.pdf`;
        const filePath = join(uploadsDir, fileName);
        await writeFile(filePath, buffer);

        const resumeUrl = `/uploads/${fileName}`;
        user.resumeUrl = resumeUrl;
        await user.save();

        return Response.json({ resumeUrl, message: 'Resume uploaded successfully' });
    } catch (error) {
        console.error('Upload error:', error);
        return Response.json({ message: error.message }, { status: 500 });
    }
}

// Delete resume route
export async function DELETE(request) {
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

        const user = await User.findById(decoded.id);
        if (!user) return Response.json({ message: 'User not found' }, { status: 404 });

        if (user.resumeUrl) {
            const fileName = user.resumeUrl.replace('/uploads/', '');
            const filePath = join(process.cwd(), 'public', 'uploads', fileName);
            try { await unlink(filePath); } catch { }
        }

        user.resumeUrl = null;
        await user.save();

        return Response.json({ message: 'Resume deleted successfully' });
    } catch (error) {
        console.error('Delete error:', error);
        return Response.json({ message: error.message }, { status: 500 });
    }
}
