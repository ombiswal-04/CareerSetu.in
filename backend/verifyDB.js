const mongoose = require('mongoose');
const dotenv = require('dotenv');
const path = require('path');
const Job = require('./models/Job');
const User = require('./models/User');

// Force IPv4 ordering to fix querySrv ETIMEOUT on Node 17+
const dns = require('dns');
if (dns.setDefaultResultOrder) {
    dns.setDefaultResultOrder('ipv4first');
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

const verify = async () => {
    await connectDB();
    try {
        const users = await User.find({});
        console.log(`Total Users: ${users.length}`);
        users.forEach(u => console.log(`- ${u.name} (${u.email}) Role: ${u.role}`));

        const jobs = await Job.find({});
        console.log(`\nTotal Jobs: ${jobs.length}`);
        jobs.forEach(j => console.log(`- ${j.title} [${j.source}]`));

        process.exit();
    } catch (error) {
        console.error(error);
        process.exit(1);
    }
};

verify();
