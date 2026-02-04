const mongoose = require('mongoose');
const dotenv = require('dotenv');
const dns = require('dns');

// Force IPv4 ordering to fix querySrv ETIMEOUT on Node 17+
if (dns.setDefaultResultOrder) {
    dns.setDefaultResultOrder('ipv4first');
}
try {
    dns.setServers(['8.8.8.8', '8.8.4.4']); // Force Google DNS
    console.log("Using Google DNS for resolution");
} catch (e) {
    console.warn("Could not set custom DNS servers", e);
}
const Job = require('./models/Job');
const User = require('./models/User');

const path = require('path');
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

const seedExternalJobs = async () => {
    await connectDB();

    try {
        // Find an admin user to assign as creator (required by schema)
        const adminUser = await User.findOne({ role: 'admin' });

        if (!adminUser) {
            console.log('No admin user found. Please create an admin user first.');
            process.exit(1);
        }

        console.log(`Assigning external jobs to Admin: ${adminUser.name} (${adminUser._id})`);

        const externalJobs = [
            {
                title: "Frontend Engineer (React)",
                company: "Google",
                location: "Bangalore",
                salary: "₹25L - ₹40L",
                jobType: "Full-time",
                description: "We are looking for an experienced Frontend Engineer...",
                source: "LinkedIn",
                applyUrl: "https://www.linkedin.com/jobs",
                createdBy: adminUser._id
            },
            {
                title: "Backend Developer (Node.js)",
                company: "Amazon",
                location: "Hyderabad",
                salary: "₹30L - ₹50L",
                jobType: "Full-time",
                description: "Join our core services team...",
                source: "Indeed",
                applyUrl: "https://www.indeed.co.in",
                createdBy: adminUser._id
            },
            {
                title: "Product Designer",
                company: "Swiggy",
                location: "Remote",
                salary: "₹18L - ₹28L",
                jobType: "Contract",
                description: "Design intuitive user experiences...",
                source: "Unstop",
                applyUrl: "https://unstop.com",
                createdBy: adminUser._id
            }
        ];

        // Insert jobs
        await Job.insertMany(externalJobs);
        console.log('External Jobs Imported Successfully!');
        process.exit();

    } catch (error) {
        console.error(`${error}`);
        process.exit(1);
    }
};

seedExternalJobs();
