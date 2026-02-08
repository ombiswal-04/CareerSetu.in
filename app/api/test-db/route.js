// Test database connection with inline DNS configuration
export async function GET() {
    try {
        // Configure DNS first
        const dns = await import('dns');

        if (dns.setDefaultResultOrder) {
            dns.setDefaultResultOrder('ipv4first');
        }
        dns.setServers(['8.8.8.8', '8.8.4.4']);
        console.log('DNS configured');

        // Dynamic import mongoose after DNS config
        const mongoose = (await import('mongoose')).default;

        const MONGODB_URI = process.env.MONGO_URI;

        if (!MONGODB_URI) {
            return Response.json({ status: 'error', message: 'MONGO_URI not found' }, { status: 500 });
        }

        console.log('Connecting to MongoDB...');
        await mongoose.connect(MONGODB_URI, {
            bufferCommands: false,
            serverSelectionTimeoutMS: 30000,
        });

        return Response.json({ status: 'ok', message: 'Database connected!' });
    } catch (error) {
        console.error('DB test error:', error);
        return Response.json({
            status: 'error',
            message: error.message,
            code: error.code
        }, { status: 500 });
    }
}
