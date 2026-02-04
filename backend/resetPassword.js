const mongoose = require('mongoose');
const dotenv = require('dotenv');
const dns = require('dns');
const path = require('path');
const User = require('./models/User');

if (dns.setDefaultResultOrder) {
    dns.setDefaultResultOrder('ipv4first');
}
try {
    dns.setServers(['8.8.8.8', '8.8.4.4']);
} catch (e) {
    console.warn("Could not set custom DNS servers", e);
}

dotenv.config({ path: path.resolve(__dirname, '.env') });

const connectDB = async () => {
    try {
        const conn = await mongoose.connect(process.env.MONGO_URI, { family: 4 });
        console.log(`MongoDB Connected: ${conn.connection.host}`);
    } catch (error) {
        console.error(`Error: ${error.message}`);
        process.exit(1);
    }
};

const reset = async () => {
    await connectDB();
    try {
        const user = await User.findOne({ email: 'biswalom04@gmail.com' });
        if (user) {
            console.log(`User found: ${user.email}. Resetting password...`);
            user.password = '123456';
            await user.save();
            console.log('Password reset to: 123456');
        } else {
            console.log('User NOT found');
        }
        process.exit();
    } catch (error) {
        console.error(error);
        process.exit(1);
    }
};

reset();
