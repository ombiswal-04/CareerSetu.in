const mongoose = require('mongoose');
const dotenv = require('dotenv');
const path = require('path');
const User = require('./models/User');

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

const makeAdmin = async () => {
    await connectDB();
    try {
        // Find any user
        const user = await User.findOne({});
        if (user) {
            console.log(`Found user: ${user.name} (${user.email}). Promoting to Admin...`);
            user.role = 'admin';
            await user.save();
            console.log(`User ${user.name} is now an Admin.`);
        } else {
            console.log('No users found in DB.');
        }
        process.exit();
    } catch (error) {
        console.error(error);
        process.exit(1);
    }
};

makeAdmin();
