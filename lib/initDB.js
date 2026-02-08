// DNS and database initialization helper
// This function MUST be called at the start of every API route handler
// BEFORE any other module imports

let dnsConfigured = false;
let mongooseInstance = null;
let connectionPromise = null;

export async function initDB() {
    // Step 1: Configure DNS (only once)
    if (!dnsConfigured) {
        const dns = await import('dns');
        if (dns.setDefaultResultOrder) {
            dns.setDefaultResultOrder('ipv4first');
        }
        dns.setServers(['8.8.8.8', '8.8.4.4']);
        dnsConfigured = true;
        console.log('DNS configured with Google DNS servers');
    }

    // Step 2: Import mongoose (after DNS is configured)
    if (!mongooseInstance) {
        mongooseInstance = (await import('mongoose')).default;
    }

    // Step 3: Connect to MongoDB (if not already connected)
    if (mongooseInstance.connection.readyState === 0 && !connectionPromise) {
        const MONGODB_URI = process.env.MONGO_URI;
        if (!MONGODB_URI) {
            throw new Error('Please define MONGO_URI in .env.local');
        }
        connectionPromise = mongooseInstance.connect(MONGODB_URI, {
            bufferCommands: false,
            serverSelectionTimeoutMS: 30000,
        });
    }

    if (connectionPromise) {
        await connectionPromise;
        connectionPromise = null;
        console.log('MongoDB connected successfully');
    }

    return mongooseInstance;
}

// Helper to get or create a model
export function getModel(mongoose, name, schemaDefinition, options = {}) {
    if (mongoose.models[name]) {
        return mongoose.models[name];
    }
    const schema = new mongoose.Schema(schemaDefinition, { timestamps: true, ...options });
    return mongoose.model(name, schema);
}
