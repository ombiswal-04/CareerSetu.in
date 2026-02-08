// Login route with proper DNS configuration
export async function POST(request) {
    try {
        // Step 1: Configure DNS FIRST
        const dns = await import('dns');
        if (dns.setDefaultResultOrder) {
            dns.setDefaultResultOrder('ipv4first');
        }
        dns.setServers(['8.8.8.8', '8.8.4.4']);

        // Step 2: Import mongoose and jwt
        const mongoose = (await import('mongoose')).default;
        const jwt = (await import('jsonwebtoken')).default;
        const bcrypt = (await import('bcryptjs')).default;

        // Step 3: Connect to MongoDB
        const MONGODB_URI = process.env.MONGO_URI;
        if (mongoose.connection.readyState === 0) {
            await mongoose.connect(MONGODB_URI, {
                bufferCommands: false,
                serverSelectionTimeoutMS: 30000,
            });
        }

        // Step 4: Get User model
        let User;
        if (mongoose.models.User) {
            User = mongoose.models.User;
        } else {
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

        // Step 5: Process login
        const { email, password } = await request.json();
        const user = await User.findOne({ email });

        if (user && (await user.matchPassword(password))) {
            const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '30d' });
            return Response.json({
                _id: user._id,
                name: user.name,
                email: user.email,
                role: user.role,
                resumeUrl: user.resumeUrl,
                token
            });
        } else {
            return Response.json({ message: 'Invalid email or password' }, { status: 401 });
        }
    } catch (error) {
        console.error('Login error:', error);
        return Response.json({ message: error.message }, { status: 500 });
    }
}
