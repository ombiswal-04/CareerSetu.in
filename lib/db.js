// MongoDB connection utility with DNS configuration for SRV resolution
// DNS must be configured BEFORE mongoose is imported

// Use globalThis for caching in serverless environments
const globalForMongoose = globalThis;

if (!globalForMongoose.mongooseCache) {
    globalForMongoose.mongooseCache = { conn: null, promise: null, dnsConfigured: false };
}

async function connectDB() {
    const cached = globalForMongoose.mongooseCache;

    // Configure DNS once before mongoose operations
    if (!cached.dnsConfigured) {
        try {
            const dns = await import('dns');

            // Force IPv4 ordering to fix querySrv ETIMEOUT on Node 17+
            if (dns.setDefaultResultOrder) {
                dns.setDefaultResultOrder('ipv4first');
            }

            // Use Google DNS for reliable resolution
            dns.setServers(['8.8.8.8', '8.8.4.4']);
            cached.dnsConfigured = true;
            console.log('DNS configured with Google DNS servers');
        } catch (e) {
            console.warn('Could not configure DNS:', e.message);
        }
    }

    // Dynamic import mongoose AFTER DNS is configured
    const mongoose = (await import('mongoose')).default;

    const MONGODB_URI = process.env.MONGO_URI;

    if (!MONGODB_URI) {
        console.error('MONGO_URI not found in environment');
        throw new Error('Please define MONGO_URI in .env.local');
    }

    if (cached.conn) {
        return cached.conn;
    }

    if (!cached.promise) {
        console.log('Connecting to MongoDB...');

        const options = {
            bufferCommands: false,
            serverSelectionTimeoutMS: 30000,
            socketTimeoutMS: 45000,
        };

        cached.promise = mongoose.connect(MONGODB_URI, options).catch((err) => {
            console.error('MongoDB connection error:', err.message);
            cached.promise = null;
            throw err;
        });
    }

    try {
        cached.conn = await cached.promise;
        console.log('MongoDB Connected successfully');
    } catch (e) {
        cached.promise = null;
        throw e;
    }

    return cached.conn;
}

export default connectDB;
