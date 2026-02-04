const express = require('express');
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
const dotenv = require('dotenv');
const cors = require('cors');
const path = require('path');
const connectDB = require('./config/db');

const authRoutes = require('./routes/authRoutes');
const jobRoutes = require('./routes/jobRoutes');
const applicationRoutes = require('./routes/applicationRoutes');
const uploadRoutes = require('./routes/uploadRoutes');

dotenv.config();

connectDB();

const app = express();

app.use(cors());
app.use(express.json());

app.use('/api/auth', authRoutes);
app.use('/api/jobs', jobRoutes);
app.use('/api/applications', applicationRoutes); // Note: frontend might use /api/applications/:jobId which maps to router.post('/:jobId')
app.use('/api/upload', uploadRoutes);

app.use('/uploads', express.static(path.join(__dirname, '/uploads')));

app.get('/', (req, res) => {
    res.send('API is running...');
});

// Global Error Handler (catch Multer errors etc)
app.use((err, req, res, next) => {
    console.error("Server Error:", err);
    res.status(400).json({ message: err.message || err });
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, console.log(`Server running on port ${PORT}`));
