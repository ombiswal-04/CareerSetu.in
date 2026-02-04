# Project Context Report

Generated on: 2026-02-04T19:17:34.468Z

## File Structure

- backend\checkUser.js
- backend\config\db.js
- backend\controllers\applicationController.js
- backend\controllers\authController.js
- backend\controllers\jobController.js
- backend\makeAdmin.js
- backend\middleware\authMiddleware.js
- backend\models\Application.js
- backend\models\Job.js
- backend\models\User.js
- backend\package.json
- backend\resetPassword.js
- backend\routes\applicationRoutes.js
- backend\routes\authRoutes.js
- backend\routes\jobRoutes.js
- backend\routes\uploadRoutes.js
- backend\seedExternal.js
- backend\server.js
- backend\verifyDB.js
- frontend\App.jsx
- frontend\components\Footer.css
- frontend\components\Footer.jsx
- frontend\components\JobCard.css
- frontend\components\JobCard.jsx
- frontend\components\Navbar.css
- frontend\components\Navbar.jsx
- frontend\components\New.jsx
- frontend\components\ProtectedRoute.jsx
- frontend\context\AuthContext.jsx
- frontend\context\ThemeContext.jsx
- frontend\index.css
- frontend\index.html
- frontend\main.jsx
- frontend\package.json
- frontend\pages\AdminDashboard.jsx
- frontend\pages\Auth.css
- frontend\pages\BrowseTalent.css
- frontend\pages\BrowseTalent.jsx
- frontend\pages\CareerHelp.css
- frontend\pages\CareerHelp.jsx
- frontend\pages\Dashboard.css
- frontend\pages\Hire.css
- frontend\pages\Hire.jsx
- frontend\pages\Home.css
- frontend\pages\Home.jsx
- frontend\pages\Jobs.css
- frontend\pages\Jobs.jsx
- frontend\pages\Login.jsx
- frontend\pages\MyJobs.css
- frontend\pages\MyJobs.jsx
- frontend\pages\MyWork.css
- frontend\pages\MyWork.jsx
- frontend\pages\Preferences.css
- frontend\pages\Preferences.jsx
- frontend\pages\Register.jsx
- frontend\src\api.js
- frontend\vite.config.js
- README.md

## File Contents

### File: backend\checkUser.js
```js
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

const check = async () => {
    await connectDB();
    try {
        const user = await User.findOne({ email: 'biswalom04@gmail.com' });
        if (user) {
            console.log(`User found: ${user.email}, Role: ${user.role}`);
        } else {
            console.log('User NOT found');
        }
        process.exit();
    } catch (error) {
        console.error(error);
        process.exit(1);
    }
};

check();

```

### File: backend\config\db.js
```js
const mongoose = require('mongoose');

const connectDB = async () => {
    try {
        const conn = await mongoose.connect(process.env.MONGO_URI, { family: 4 });
        console.log(`MongoDB Connected: ${conn.connection.host}`);
    } catch (error) {
        console.error(`Error: ${error.message}`);
        process.exit(1);
    }
};

module.exports = connectDB;

```

### File: backend\controllers\applicationController.js
```js
const Application = require('../models/Application');
const Job = require('../models/Job');

// @desc    Apply for a job
// @route   POST /api/applications/:jobId
// @access  Private
const applyForJob = async (req, res) => {
    const { jobId } = req.params;

    const job = await Job.findById(jobId);

    if (!job) {
        return res.status(404).json({ message: 'Job not found' });
    }

    const alreadyApplied = await Application.findOne({
        userId: req.user._id,
        jobId: jobId
    });

    if (alreadyApplied) {
        return res.status(400).json({ message: 'You have already applied for this job' });
    }

    const application = await Application.create({
        userId: req.user._id,
        jobId: jobId,
        status: 'applied'
    });

    res.status(201).json(application);
};

// @desc    Get user applications (My Work)
// @route   GET /api/my-work
// @access  Private
const getMyApplications = async (req, res) => {
    const applications = await Application.find({ userId: req.user._id }).populate('jobId');
    res.json(applications);
};

// @desc    Get all applications (Admin)
// @route   GET /api/admin/applications
// @access  Private/Admin
const getAllApplications = async (req, res) => {
    const applications = await Application.find({})
        .populate('userId', 'name email resumeUrl')
        .populate('jobId', 'title company');
    res.json(applications);
};

// @desc    Update application status (Accept/Reject)
// @route   PUT /api/admin/applications/:id/status
// @access  Private/Admin
const updateApplicationStatus = async (req, res) => {
    const { status } = req.body; // accepted or rejected
    const application = await Application.findById(req.params.id);

    if (application) {
        application.status = status;
        const updatedApplication = await application.save();
        res.json(updatedApplication);
    } else {
        res.status(404).json({ message: 'Application not found' });
    }
};

// @desc    Schedule interview
// @route   PUT /api/admin/applications/:id/schedule
// @access  Private/Admin
const scheduleInterview = async (req, res) => {
    const { interviewDate, interviewTime } = req.body;
    const application = await Application.findById(req.params.id);

    if (application) {
        application.status = 'interview';
        application.interviewDate = interviewDate;
        application.interviewTime = interviewTime;
        const updatedApplication = await application.save();
        res.json(updatedApplication);
    } else {
        res.status(404).json({ message: 'Application not found' });
    }
};

module.exports = {
    applyForJob,
    getMyApplications,
    getAllApplications,
    updateApplicationStatus,
    scheduleInterview
};

```

### File: backend\controllers\authController.js
```js
const User = require('../models/User');
const jwt = require('jsonwebtoken');

const generateToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_SECRET, {
        expiresIn: '30d'
    });
};

// @desc    Register a new user
// @route   POST /api/auth/register
// @access  Public
const registerUser = async (req, res) => {
    try {
        const { name, email, password, role } = req.body;
        console.log("Register Request:", { name, email, requestedRole: role });

        const userExists = await User.findOne({ email });

        if (userExists) {
            return res.status(400).json({ message: 'User already exists' });
        }

        // Enforce Admin Restriction: Email + Specific Password
        let userRole = 'user';
        if (email === 'biswalom04@gmail.com' && password === 'Omsoa23') {
            userRole = 'admin';
        }

        const user = await User.create({
            name,
            email,
            password,
            role: userRole
        });

        if (user) {
            res.status(201).json({
                _id: user._id,
                name: user.name,
                email: user.email,
                role: user.role,
                resumeUrl: user.resumeUrl,
                token: generateToken(user._id)
            });
        } else {
            res.status(400).json({ message: 'Invalid user data' });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: error.message });
    }
};

// @desc    Auth user & get token
// @route   POST /api/auth/login
// @access  Public
const authUser = async (req, res) => {
    const { email, password } = req.body;

    const user = await User.findOne({ email });

    if (user && (await user.matchPassword(password))) {
        res.json({
            _id: user._id,
            name: user.name,
            email: user.email,
            role: user.role,
            resumeUrl: user.resumeUrl,
            token: generateToken(user._id)
        });
    } else {
        res.status(401).json({ message: 'Invalid email or password' });
    }
};

module.exports = { registerUser, authUser };

```

### File: backend\controllers\jobController.js
```js
const Job = require('../models/Job');

// @desc    Create a job
// @route   POST /api/jobs
// @access  Private/Admin
const createJob = async (req, res) => {
    const { title, company, location, salary, jobType, description } = req.body;

    const job = new Job({
        title,
        company,
        location,
        salary,
        jobType,
        description,
        createdBy: req.user._id
    });

    const createdJob = await job.save();
    res.status(201).json(createdJob);
};

// @desc    Get all jobs
// @route   GET /api/jobs
// @access  Private
const getJobs = async (req, res) => {
    const jobs = await Job.find({});
    res.json(jobs);
};


// @desc    Delete a job
// @route   DELETE /api/jobs/:id
// @access  Private/Admin
const deleteJob = async (req, res) => {
    try {
        const job = await Job.findById(req.params.id);

        if (job) {
            await job.deleteOne();
            res.json({ message: 'Job removed' });
        } else {
            res.status(404).json({ message: 'Job not found' });
        }
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};


// @desc    Update a job
// @route   PUT /api/jobs/:id
// @access  Private/Admin
const updateJob = async (req, res) => {
    try {
        const job = await Job.findById(req.params.id);

        if (job) {
            job.title = req.body.title || job.title;
            job.company = req.body.company || job.company;
            job.location = req.body.location || job.location;
            job.salary = req.body.salary || job.salary;
            job.jobType = req.body.jobType || job.jobType;
            job.description = req.body.description || job.description;
            job.source = req.body.source || job.source; // Allow updating source
            job.applyUrl = req.body.applyUrl || job.applyUrl;

            const updatedJob = await job.save();
            res.json(updatedJob);
        } else {
            res.status(404).json({ message: 'Job not found' });
        }
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

module.exports = { createJob, getJobs, deleteJob, updateJob };

```

### File: backend\makeAdmin.js
```js
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

```

### File: backend\middleware\authMiddleware.js
```js
const jwt = require('jsonwebtoken');
const User = require('../models/User');

const protect = async (req, res, next) => {
    let token;

    if (
        req.headers.authorization &&
        req.headers.authorization.startsWith('Bearer')
    ) {
        try {
            token = req.headers.authorization.split(' ')[1];

            const decoded = jwt.verify(token, process.env.JWT_SECRET);

            req.user = await User.findById(decoded.id).select('-password');

            next();
        } catch (error) {
            console.error(error);
            res.status(401).json({ message: 'Not authorized, token failed' });
        }
    }

    if (!token) {
        res.status(401).json({ message: 'Not authorized, no token' });
    }
};

const admin = (req, res, next) => {
    if (req.user && req.user.role === 'admin') {
        next();
    } else {
        res.status(401).json({ message: 'Not authorized as an admin' });
    }
};

module.exports = { protect, admin };

```

### File: backend\models\Application.js
```js
const mongoose = require('mongoose');

const applicationSchema = mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    jobId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Job',
        required: true
    },
    status: {
        type: String,
        enum: ['applied', 'interview', 'rejected', 'accepted'],
        default: 'applied'
    },
    interviewDate: {
        type: String, // Storing as string or Date as preferred, using String for simplicity with Date picker
        default: null
    },
    interviewTime: {
        type: String,
        default: null
    },
    appliedAt: {
        type: Date,
        default: Date.now
    }
}, {
    timestamps: true
});

const Application = mongoose.model('Application', applicationSchema);
module.exports = Application;

```

### File: backend\models\Job.js
```js
const mongoose = require('mongoose');

const jobSchema = mongoose.Schema({
    title: {
        type: String,
        required: true
    },
    company: {
        type: String,
        required: true
    },
    location: {
        type: String,
        required: true
    },
    salary: {
        type: String,
        required: true
    },
    jobType: {
        type: String,
        required: true // e.g., Full-time, Part-time
    },
    description: {
        type: String,
        required: true
    },
    source: {
        type: String,
        enum: ['Admin', 'CareerSetu', 'LinkedIn', 'Indeed', 'Naukri', 'Unstop', 'External'],
        default: 'CareerSetu'
    },
    applyUrl: {
        type: String,
        required: false // Only required for external jobs
    },
    createdBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    }
}, {
    timestamps: true
});

const Job = mongoose.model('Job', jobSchema);
module.exports = Job;

```

### File: backend\models\User.js
```js
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    role: {
        type: String,
        enum: ['user', 'admin'],
        default: 'user'
    },
    resumeUrl: {
        type: String,
        default: null
    }
}, {
    timestamps: true
});

userSchema.methods.matchPassword = async function (enteredPassword) {
    return await bcrypt.compare(enteredPassword, this.password);
};

userSchema.pre('save', async function () {
    if (!this.isModified('password')) {
        return;
    }
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
});

const User = mongoose.model('User', userSchema);
module.exports = User;

```

### File: backend\package.json
```json
{
  "name": "backend",
  "version": "1.0.0",
  "description": "",
  "main": "server.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1",
    "start": "node server.js"
  },
  "keywords": [],
  "author": "",
  "license": "ISC",
  "type": "commonjs",
  "dependencies": {
    "bcryptjs": "^3.0.3",
    "cors": "^2.8.6",
    "dotenv": "^17.2.3",
    "express": "^5.2.1",
    "jsonwebtoken": "^9.0.3",
    "mongoose": "^9.1.5",
    "multer": "^2.0.2"
  },
  "devDependencies": {
    "nodemon": "^3.1.11"
  }
}

```

### File: backend\resetPassword.js
```js
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

```

### File: backend\routes\applicationRoutes.js
```js
const express = require('express');
const router = express.Router();
const {
    applyForJob,
    getMyApplications,
    getAllApplications,
    updateApplicationStatus,
    scheduleInterview
} = require('../controllers/applicationController');
const { protect, admin } = require('../middleware/authMiddleware');

router.post('/:jobId', protect, applyForJob); // Apply for a job
router.get('/my-work', protect, getMyApplications); // Get logged in user's applications

// Admin routes
router.get('/admin/all', protect, admin, getAllApplications);
router.put('/admin/:id/status', protect, admin, updateApplicationStatus);
router.put('/admin/:id/schedule', protect, admin, scheduleInterview);

module.exports = router;

```

### File: backend\routes\authRoutes.js
```js
const express = require('express');
const router = express.Router();
const { registerUser, authUser } = require('../controllers/authController');

router.post('/register', registerUser);
router.post('/login', authUser);

module.exports = router;

```

### File: backend\routes\jobRoutes.js
```js
const express = require('express');
const router = express.Router();
const { createJob, getJobs } = require('../controllers/jobController');
const { protect, admin } = require('../middleware/authMiddleware');

router.route('/').post(protect, admin, createJob).get(protect, getJobs);
router.route('/:id').delete(protect, admin, require('../controllers/jobController').deleteJob).put(protect, admin, require('../controllers/jobController').updateJob);

module.exports = router;

```

### File: backend\routes\uploadRoutes.js
```js
const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const { protect } = require('../middleware/authMiddleware');
const User = require('../models/User');

const storage = multer.diskStorage({
    destination(req, file, cb) {
        cb(null, 'uploads/');
    },
    filename(req, file, cb) {
        cb(null, `${req.user._id}-${Date.now()}${path.extname(file.originalname)}`);
    }
});

const checkFileType = (file, cb) => {
    const filetypes = /pdf/;
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = filetypes.test(file.mimetype);

    if (extname && mimetype) {
        return cb(null, true);
    } else {
        cb('PDF only!');
    }
};

const upload = multer({
    storage,
    fileFilter: function (req, file, cb) {
        checkFileType(file, cb);
    }
});

// @desc    Upload resume
// @route   POST /api/upload
// @access  Private
router.post('/', protect, (req, res, next) => {
    // Wrap multer in a promise or just handle errors immediately
    const uploadSingle = upload.single('resume');

    uploadSingle(req, res, async function (err) {
        if (err) {
            console.error("Multer Error:", err);
            return res.status(400).json({ message: err.message || err });
        }

        console.log("File uploaded to temp path:", req.file);

        if (!req.file) {
            console.error("No file received");
            return res.status(400).json({ message: 'No file uploaded' });
        }

        try {
            console.log("Finding user:", req.user._id);
            const user = await User.findById(req.user._id);

            if (user) {
                user.resumeUrl = `/${req.file.path.replace(/\\/g, '/')}`; // Normalize path
                console.log("Saving user with resumeUrl:", user.resumeUrl);
                await user.save();

                res.json({
                    success: true,
                    message: 'Resume uploaded successfully',
                    filePath: user.resumeUrl,
                    fileName: req.file.originalname
                });
            } else {
                console.error("User not found in DB");
                res.status(404).json({ message: 'User not found' });
            }
        } catch (dbError) {
            console.error("Database Error:", dbError);
            res.status(500).json({ message: 'Database save failed: ' + dbError.message });
        }
    });
});

// @desc    Delete resume
// @route   DELETE /api/upload
// @access  Private
router.delete('/', protect, async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        if (user) {
            // Optional: Delete file from filesystem if needed (requires fs module)
            // const fs = require('fs');
            // const filePath = path.join(__dirname, '..', user.resumeUrl);
            // if (fs.existsSync(filePath)) fs.unlinkSync(filePath);

            user.resumeUrl = null;
            await user.save();
            res.json({ success: true, message: 'Resume deleted successfully' });
        } else {
            res.status(404).json({ message: 'User not found' });
        }
    } catch (error) {
        console.error("Delete Error:", error);
        res.status(500).json({ message: 'Server error' });
    }
});

module.exports = router;

```

### File: backend\seedExternal.js
```js
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

```

### File: backend\server.js
```js
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

```

### File: backend\verifyDB.js
```js
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

```

### File: frontend\App.jsx
```jsx
import { HashRouter, Routes, Route, useLocation } from 'react-router-dom'
import Navbar from './components/Navbar'
import Footer from './components/Footer'
import Home from './pages/Home'
import Jobs from './pages/Jobs'

import BrowseTalent from './pages/BrowseTalent'
import CareerHelp from './pages/CareerHelp'
import Preferences from './pages/Preferences'
import Login from './pages/Login'
import Register from './pages/Register'
import ProtectedRoute from './components/ProtectedRoute'
import MyWork from './pages/MyWork'
import AdminDashboard from './pages/AdminDashboard'
import MyJobs from './pages/MyJobs'
import Hire from './pages/Hire'

const AUTH_ROUTES = ['/login', '/register']

function AppLayout() {
  return (
    <div className="app-layout">
      <div className="app-main">
        <Navbar />
        <div className="app-content">
          <Routes>
            <Route path="/" element={<Home />} />
            {/* Protected Routes for User */}
            <Route element={<ProtectedRoute />}>
              <Route path="/jobs" element={<Jobs />} />
              <Route path="/talents" element={<BrowseTalent />} />
              <Route path="/my-work" element={<MyWork />} />
              <Route path="/my-jobs" element={<MyJobs />} />
              <Route path="/career" element={<CareerHelp />} />

              <Route path="/preferences" element={<Preferences />} />
            </Route>

            {/* Protected Routes for Admin */}
            <Route element={<ProtectedRoute adminOnly={true} />}>
              <Route path="/admin" element={<AdminDashboard />} />
              <Route path="/hire" element={<Hire />} />
            </Route>



            <Route path="/login" element={<Login />} />
            <Route path="/register" element={<Register />} />
          </Routes>
        </div>
        <Footer />
      </div>
    </div>
  )
}

import { ThemeProvider } from './context/ThemeContext'
import { AuthProvider } from './context/AuthContext'

export default function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <HashRouter>
          <AppLayout />
        </HashRouter>
      </AuthProvider>
    </ThemeProvider>
  )
}

```

### File: frontend\components\Footer.css
```css
.footer {
  margin-top: auto;
  padding: 2.5rem 0 1.5rem;
  /* Reduced padding by ~35-40% */
  background: var(--bg-tertiary);
  border-top: 1px solid var(--border-color);
  color: var(--text-secondary);
  font-size: 0.875rem;
  /* Base font size reduction */
}

.footer__grid {
  display: grid;
  grid-template-columns: 1fr;
  gap: 2rem;
  margin-bottom: 2rem;
  /* Tighter spacing */
}

@media (min-width: 640px) {
  .footer__grid {
    grid-template-columns: repeat(2, 1fr);
  }
}

@media (min-width: 1024px) {
  .footer__grid {
    grid-template-columns: 1.5fr 1fr 1fr 1fr;
    gap: 1.5rem;
  }
}

.footer__col {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.footer__brand-col {
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
  /* Space between logo and social section */
}

.footer__logo {
  font-family: var(--font-heading);
  font-size: 1.75rem;
  font-weight: 700;
  color: rgb(35, 190, 139);
  text-decoration: none;
  letter-spacing: -0.02em;
}

[data-theme="dark"] .footer__logo {
  color: rgb(35, 190, 139);
}

.footer__socials {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.footer__social-title {
  font-size: 0.95rem;
  font-weight: 600;
  color: var(--text-primary);
}

.footer__social-icons {
  display: flex;
  gap: 1rem;
}

.footer__icon {
  font-size: 1.25rem;
  text-decoration: none;
  opacity: 0.7;
  transition: opacity 0.2s ease, transform 0.2s ease;
  filter: grayscale(100%);
}

.footer__icon:hover {
  opacity: 1;
  transform: translateY(-2px);
  filter: grayscale(0%);
}

.footer__list {
  list-style: none;
  padding: 0;
  margin: 0;
  display: flex;
  flex-direction: column;
  gap: 0.8rem;
  /* Relaxed spacing for links */
}

.footer__item {
  font-size: 0.9rem;
  color: var(--text-secondary);
  line-height: normal;
}

.footer__link {
  color: var(--text-secondary);
  text-decoration: none;
  transition: color 0.2s ease;
}

.footer__link:hover {
  color: var(--accent-primary);
  /* text-decoration: underline; Removed underline preference */
}

/* Footer Bottom */
.footer__bottom {
  margin-top: 2rem;
  padding-top: 2rem;
  border-top: 1px solid var(--border-color);
  text-align: center;
}

.footer__copyright {
  font-size: 0.85rem;
  color: var(--text-tertiary);
}
```

### File: frontend\components\Footer.jsx
```jsx
import { Link } from 'react-router-dom'
import './Footer.css'

export default function Footer() {
  const currentYear = new Date().getFullYear()

  return (
    <footer className="footer">
      <div className="container">
        <div className="footer__grid">
          {/* Column 1: Brand & Connect */}
          <div className="footer__col footer__brand-col">
            <Link to="/" className="footer__logo">
              CareerSetu
            </Link>
            <div className="footer__socials">
              <h3 className="footer__social-title">Connect with us</h3>
              <div className="footer__social-icons">
                <a href="#" className="footer__icon" aria-label="Facebook">📘</a>
                <a href="#" className="footer__icon" aria-label="Instagram">📷</a>
                <a href="#" className="footer__icon" aria-label="Twitter">✖️</a>
                <a href="#" className="footer__icon" aria-label="LinkedIn">💼</a>
              </div>
            </div>
          </div>

          {/* Column 2: Company Links */}
          <div className="footer__col">
            <ul className="footer__list">
              <li className="footer__item"><Link to="/about" className="footer__link">About us</Link></li>
              <li className="footer__item"><Link to="/careers" className="footer__link">Careers</Link></li>
              <li className="footer__item"><Link to="/employer" className="footer__link">Employer home</Link></li>
              <li className="footer__item"><Link to="/sitemap" className="footer__link">Sitemap</Link></li>
              <li className="footer__item"><Link to="/credits" className="footer__link">Credits</Link></li>
            </ul>
          </div>

          {/* Column 3: Help & Support */}
          <div className="footer__col">
            <ul className="footer__list">
              <li className="footer__item"><Link to="/help" className="footer__link">Help center</Link></li>
              <li className="footer__item"><a href="#" className="footer__link">Summons/Notices</a></li>
              <li className="footer__item"><a href="#" className="footer__link">Grievances</a></li>
              <li className="footer__item"><a href="#" className="footer__link">Report issue</a></li>
            </ul>
          </div>

          {/* Column 4: Legal & Safety */}
          <div className="footer__col">
            <ul className="footer__list">
              <li className="footer__item"><Link to="/privacy" className="footer__link">Privacy policy</Link></li>
              <li className="footer__item"><Link to="/terms" className="footer__link">Terms & conditions</Link></li>
              <li className="footer__item"><a href="#" className="footer__link">Fraud alert</a></li>
              <li className="footer__item"><a href="#" className="footer__link">Trust & safety</a></li>
            </ul>
          </div>
        </div>

        <div className="footer__bottom">
          <p className="footer__copyright">
            © {currentYear} CareerSetu. Proudly Built with love in Bhubaneswar ❤️
          </p>
        </div>
      </div>
    </footer>
  )
}

```

### File: frontend\components\JobCard.css
```css
.job-card {
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  padding: 1.5rem;
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-sm);
  display: flex;
  flex-direction: column;
  gap: 1.25rem;
  transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
  position: relative;
  overflow: hidden;
  height: 100%;
}

.job-card:hover {
  transform: translateY(-5px);
  box-shadow: var(--shadow-md);
  border-color: var(--accent-secondary);
}

[data-theme="dark"] .job-card:hover {
  border-color: var(--accent-primary);
  box-shadow: 0 10px 20px -5px rgba(0, 0, 0, 0.4);
}

/* Header: Logo + Title/Company */
.job-card__header {
  display: flex;
  gap: 1rem;
  align-items: flex-start;
}

.job-card__logo {
  flex-shrink: 0;
}

.job-card__logo-placeholder {
  width: 48px;
  height: 48px;
  background: var(--bg-tertiary);
  color: var(--text-primary);
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 700;
  font-size: 1.25rem;
  border-radius: var(--radius-md);
  border: 1px solid var(--border-color);
}

.job-card__header-content {
  flex: 1;
  min-width: 0;
  /* needed for text truncation flex child */
}

.job-card__title {
  font-family: var(--font-heading);
  font-size: 1.1rem;
  font-weight: 700;
  color: var(--text-primary);
  margin-bottom: 0.25rem;
  line-height: 1.35;

  /* Text Clamping */
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  overflow: hidden;
}

.job-card__company {
  font-size: 0.9rem;
  color: var(--text-secondary);
  font-weight: 500;

  /* Text Clamping */
  display: -webkit-box;
  -webkit-line-clamp: 1;
  -webkit-box-orient: vertical;
  overflow: hidden;
}

/* Body: Tags, etc */
.job-card__body {
  margin-bottom: 0.5rem;
}

.job-card__tags {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.75rem;
}

.job-card__tag {
  padding: 0.25rem 0.75rem;
  background: var(--bg-tertiary);
  color: var(--text-secondary);
  font-size: 0.8rem;
  border-radius: var(--radius-pill);
  font-weight: 600;
  white-space: nowrap;
}

.job-card__location {
  display: flex;
  align-items: center;
  gap: 0.25rem;
  font-size: 0.85rem;
  color: var(--text-tertiary);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.job-card__location-icon {
  font-size: 0.9rem;
  opacity: 0.7;
}

/* Footer: Salary + Button */
.job-card__footer {
  margin-top: auto;
  /* PINS footer to bottom */
  display: flex;
  flex-direction: column;
  gap: 1rem;
  padding-top: 1rem;
  border-top: 1px solid var(--border-color);
}

.job-card__salary-wrapper {
  min-height: 28px;
  /* reserves space if empty */
  display: flex;
  align-items: center;
}

.job-card__salary {
  font-weight: 700;
  color: var(--text-primary);
  font-size: 1rem;
  background: var(--bg-tertiary);
  padding: 0.25rem 0.75rem;
  border-radius: var(--radius-sm);
  display: inline-block;
}

.job-card__salary--hidden {
  opacity: 0;
  /* Keeps layout stable */
}

.job-card__apply-btn {
  width: 100%;
  padding: 0.75rem;
  background: #10B981;
  /* Brand Green */
  color: #ffffff;
  border-radius: var(--radius-md);
  font-weight: 600;
  font-size: 0.95rem;
  transition: all 0.2s ease;
  box-shadow: var(--shadow-sm);
}

.job-card__apply-btn:hover {
  background: #059669;
  /* Darker Green on hover */
  color: #ffffff;
  transform: translateY(-2px);
  box-shadow: var(--shadow-md);
}

[data-theme="dark"] .job-card__apply-btn {
  background: var(--accent-primary);
  color: var(--accent-secondary);
  /* Dark text on light button */
  font-weight: 700;
}

[data-theme="dark"] .job-card__apply-btn:hover {
  background: var(--accent-hover);
}
```

### File: frontend\components\JobCard.jsx
```jsx
import './JobCard.css'

export default function JobCard({ job, isApplied, onApply }) {
  const {
    title,
    company,
    location,
    jobType = 'Full-time', // Map jobType from backend to type if needed, or use jobType
    salary,
    source = 'Admin',
    applyUrl,
    logoPlaceholder = true,
  } = job

  // Normalize source display and check if internal
  const displaySource = source === 'Admin' ? 'CareerSetu' : source
  const isInternal = displaySource === 'CareerSetu'

  return (
    <article className="job-card">
      <div className="job-card__header">
        <div className="job-card__logo">
          {logoPlaceholder ? (
            <div className="job-card__logo-placeholder" aria-hidden>
              {company?.charAt(0) || '?'}
            </div>
          ) : null}
        </div>
        <div className="job-card__header-content">
          <h3 className="job-card__title" title={title}>{title}</h3>
          <p className="job-card__company" title={company}>{company}</p>
          <span className="job-card__source-badge">
            Source: {displaySource}
          </span>
        </div>
      </div>

      <div className="job-card__body">
        <div className="job-card__tags">
          <span className="job-card__tag">{jobType}</span>
          <span className="job-card__location">
            <span className="job-card__location-icon">📍</span>
            {location}
          </span>
        </div>
      </div>

      <div className="job-card__footer">
        <div className="job-card__salary-wrapper">
          {salary ? (
            <p className="job-card__salary">{salary}</p>
          ) : (
            <p className="job-card__salary job-card__salary--hidden">Best in Industry</p>
          )}
        </div>
        <button
          type="button"
          className={`job-card__apply-btn ${isApplied ? 'job-card__apply-btn--applied' : ''}`}
          onClick={() => {
            if (!isInternal) {
              if (applyUrl) window.open(applyUrl, '_blank')
            } else {
              onApply && onApply(job._id)
            }
          }}
          disabled={isApplied || (!isInternal && !applyUrl)}
        >
          {!isInternal ? `Apply on ${displaySource}` : (isApplied ? 'Applied' : 'Apply Now')}
        </button>
      </div>
    </article>
  )
}

```

### File: frontend\components\Navbar.css
```css
.navbar {
  position: sticky;
  top: 0;
  z-index: 100;
  background: var(--glass-bg);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  box-shadow: var(--shadow-sm);
  border-bottom: 1px solid var(--border-color);
  transition: background 0.3s ease, border-color 0.3s ease;
}

.navbar__container {
  display: flex;
  align-items: center;
  justify-content: space-between;
  min-height: 72px;
  gap: 1.5rem;
}

.navbar__logo {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  font-family: var(--font-heading);
  font-size: 1.85rem;
  font-weight: 700;
  color: #10B981;
  /* Brand Green */
  letter-spacing: -0.02em;
  transition: color 0.2s ease;
  text-decoration: none;
  /* Removed underline */
  margin-right: auto;
  /* Push nav to right if needed, but flex handles naturally */
}


.navbar__sidebar-toggle {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 40px;
  height: 40px;
  background: transparent;
  border: 1px solid transparent;
  border-radius: var(--radius-sm);
  color: var(--text-secondary);
  font-size: 1.5rem;
  cursor: pointer;
  transition: all 0.2s ease;
  margin-right: 0.25rem;
}

.navbar__sidebar-toggle:hover {
  background: var(--bg-tertiary);
  color: var(--text-primary);
}

.navbar__toggle {
  display: flex;
  flex-direction: column;
  justify-content: center;
  gap: 5px;
  width: 40px;
  height: 40px;
  padding: 8px;
  background: none;
  border: 1px solid var(--border-color);
  border-radius: var(--radius-sm);
  transition: background 0.2s ease, border-color 0.2s ease;
  color: var(--text-primary);
  align-items: center;
}

.navbar__toggle:hover {
  background: var(--bg-tertiary);
  border-color: var(--text-primary);
}

@media (min-width: 1024px) {
  .navbar__toggle {
    display: none;
  }
}

.navbar__toggle-bar {
  display: block;
  width: 20px;
  height: 2px;
  background: currentColor;
  border-radius: 1px;
  transition: transform 0.2s ease, opacity 0.2s ease;
}

.navbar__toggle-bar.open:nth-child(1) {
  transform: translateY(7px) rotate(45deg);
}

.navbar__toggle-bar.open:nth-child(2) {
  opacity: 0;
}

.navbar__toggle-bar.open:nth-child(3) {
  transform: translateY(-7px) rotate(-45deg);
}

/* Nav Links - Desktop & Mobile */
.navbar__nav {
  display: none;
  flex-direction: column;
  position: absolute;
  top: 100%;
  left: 0;
  right: 0;
  background: var(--bg-secondary);
  box-shadow: var(--shadow-lg);
  padding: 1.25rem;
  gap: 0.5rem;
  border-bottom: 1px solid var(--border-color);
}

.navbar__nav--open {
  display: flex;
  /* Show mobile menu */
}

@media (min-width: 1024px) {
  .navbar__nav {
    position: static;
    display: flex;
    flex-direction: row;
    align-items: center;
    flex: 1;
    justify-content: flex-end;
    box-shadow: none;
    padding: 0;
    gap: 0.75rem;
    /* Consistent gap between items */
    border-bottom: none;
    background: transparent;
  }
}

.navbar__link {
  display: block;
  padding: 0.6rem 1rem;
  font-size: 0.95rem;
  font-weight: 700;
  color: rgb(15, 61, 62);
  border-radius: var(--radius-pill);
  /* Pill shape */
  text-decoration: none;
  transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
  /* Smooth transition */
}

[data-theme="dark"] .navbar__link {
  color: rgb(16, 185, 129);
}

.navbar__link:hover {
  background: var(--bg-tertiary);
  color: var(--text-primary);
  transform: translateY(-1px);
  /* Subtle lift */
}

/* Active State for NavLink */
.navbar__link.active:not(.navbar__link--outline):not(.navbar__link--primary) {
  background: var(--bg-tertiary);
  color: rgb(15, 61, 62);
  font-weight: 700;
  box-shadow: inset 0 0 0 1px var(--border-color);
  /* Subtle border for active */
}

[data-theme="dark"] .navbar__link.active:not(.navbar__link--outline):not(.navbar__link--primary) {
  color: rgb(16, 185, 129);
}

/* Buttons (Login / Register) */
.navbar__link--outline {
  border: 1px solid var(--border-color);
  background: transparent;
  color: rgb(15, 61, 62);
  font-weight: 600;
  border-radius: var(--radius-md);
  /* Keep buttons slightly less rounded than nav pills */
}

[data-theme="dark"] .navbar__link--outline {
  color: rgb(16, 185, 129);
  border-color: rgb(16, 185, 129);
}

.navbar__link--primary {
  background: var(--accent-primary);
  color: #ffffff;
  border: none;
  font-weight: 600;
  box-shadow: var(--shadow-sm);
}

[data-theme="dark"] .navbar__link--primary {
  color: #ffffff;
}


/* Theme Toggle Alignment */
.navbar__theme-toggle {
  background: var(--bg-tertiary);
  border: 1px solid transparent;
  color: var(--text-secondary);
  font-size: 1.1rem;
  cursor: pointer;
  width: 40px;
  height: 40px;
  border-radius: var(--radius-pill);
  display: flex;
  align-items: center;
  justify-content: center;
  transition: all 0.2s ease;
  margin-left: 0.5rem;
  /* Extra space from last nav item */
}

.navbar__theme-toggle:hover {
  background-color: var(--border-color);
  color: var(--text-primary);
  transform: rotate(15deg);
}

/* User Menu Styling */
.navbar__user-menu {
  display: flex;
  align-items: center;
  gap: 1rem;
  padding: 0.5rem 0;
}

.navbar__user-name {
  font-weight: 600;
  color: rgb(15, 61, 62);
  font-size: 0.95rem;
  letter-spacing: -0.01em;
}

[data-theme="dark"] .navbar__user-name {
  color: rgb(16, 185, 129);
}

/* Mobile Adjustments for User Menu */
@media (max-width: 1023px) {
  .navbar__user-menu {
    flex-direction: column;
    align-items: flex-start;
    width: 100%;
    padding-top: 1rem;
    margin-top: 0.5rem;
    border-top: 1px dashed var(--border-color);
    gap: 1rem;
  }

  .navbar__user-name {
    font-size: 1.1rem;
    /* Slightly larger on mobile for readability */
    color: var(--accent-primary);
  }

  /* Make logout button full width on mobile */
  .navbar__user-menu .navbar__link--outline {
    width: 100%;
    text-align: center;
    justify-content: center;
  }
}

/* Desktop Adjustments */
@media (min-width: 1024px) {
  .navbar__user-menu {
    flex-direction: row;
    padding: 0;
    margin: 0;
    border: none;
    margin-left: 1rem;
    /* Separate from other links */
    border-left: 1px solid var(--border-color);
    /* Vertical divider */
    padding-left: 1.5rem;
  }
}
```

### File: frontend\components\Navbar.jsx
```jsx
import { useState } from 'react'
import { Link, NavLink } from 'react-router-dom'
import { useTheme } from '../context/ThemeContext'
import { useAuth } from '../context/AuthContext'
import './Navbar.css'

export default function Navbar() {
  const [menuOpen, setMenuOpen] = useState(false)
  const { theme, toggleTheme } = useTheme()
  const { user, logout } = useAuth()

  const toggleMenu = () => setMenuOpen((prev) => !prev)
  const closeMenu = () => setMenuOpen(false)

  return (
    <header className="navbar">
      <div className="navbar__container container">
        <Link to="/" className="navbar__logo" onClick={closeMenu}>
          CareerSetu
        </Link>

        <button
          type="button"
          className="navbar__toggle"
          aria-label="Toggle menu"
          aria-expanded={menuOpen}
          onClick={toggleMenu}
        >
          <span className={menuOpen ? 'navbar__toggle-bar open' : 'navbar__toggle-bar'} />
          <span className={menuOpen ? 'navbar__toggle-bar open' : 'navbar__toggle-bar'} />
          <span className={menuOpen ? 'navbar__toggle-bar open' : 'navbar__toggle-bar'} />
        </button>

        <nav className={`navbar__nav ${menuOpen ? 'navbar__nav--open' : ''}`}>
          {(!user || user.role !== 'admin') && (
            <>
              <NavLink to="/jobs" className="navbar__link" onClick={closeMenu}>
                Jobs
              </NavLink>
              <NavLink to="/talents" className="navbar__link" onClick={closeMenu}>
                Top Mentors
              </NavLink>
            </>
          )}
          {user && user.role !== 'admin' && (
            <NavLink to="/my-work" className="navbar__link" onClick={closeMenu}>
              Career
            </NavLink>
          )}
          {user && user.role === 'admin' && (
            <>
              <NavLink to="/hire" className="navbar__link" onClick={closeMenu}>
                Hire
              </NavLink>
              <NavLink to="/admin" className="navbar__link" onClick={closeMenu}>
                Admin Dashboard
              </NavLink>
            </>
          )}
          {user ? (
            <div className="navbar__user-menu">
              <Link to="/my-work" className="navbar__user-name" onClick={closeMenu} style={{ textDecoration: 'none', cursor: 'pointer' }}>
                Hi, {user.name}
              </Link>
              <button onClick={logout} className="navbar__link navbar__link--outline">Logout</button>
            </div>
          ) : (
            <>
              <Link to="/login" className="navbar__link navbar__link--outline" onClick={closeMenu}>
                Login
              </Link>
              <Link to="/register" className="navbar__link navbar__link--primary" onClick={closeMenu}>
                Register Now
              </Link>
            </>
          )}
          <button
            className="navbar__theme-toggle"
            onClick={toggleTheme}
            aria-label="Toggle theme"
          >
            {theme === 'dark' ? '☀️' : '🌙'}
          </button>
        </nav>
      </div>
    </header>
  )
}

```

### File: frontend\components\New.jsx
```jsx
export default function New() {
    return <h1>Hello</h1>;
}
```

### File: frontend\components\ProtectedRoute.jsx
```jsx
import { Navigate, Outlet } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

const ProtectedRoute = ({ adminOnly = false }) => {
    const { user, loading } = useAuth();

    if (loading) {
        return <div>Loading...</div>;
    }

    if (!user) {
        return <Navigate to="/login" replace />;
    }

    if (adminOnly && user.role !== 'admin') {
        return <Navigate to="/" replace />;
    }

    return <Outlet />;
};

export default ProtectedRoute;

```

### File: frontend\context\AuthContext.jsx
```jsx
import { createContext, useState, useEffect, useContext } from 'react';
import API from '../src/api';

const AuthContext = createContext();

export const useAuth = () => useContext(AuthContext);

export const AuthProvider = ({ children }) => {
    const [user, setUser] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const storedUser = localStorage.getItem('user');
        if (storedUser) {
            try {
                setUser(JSON.parse(storedUser));
            } catch (e) {
                console.error("Failed to parse user from local storage", e);
                localStorage.removeItem('user');
            }
        }
        setLoading(false);
    }, []);

    const login = async (email, password) => {
        try {
            const { data } = await API.post('/api/auth/login', { email, password });
            localStorage.setItem('user', JSON.stringify(data));
            setUser(data);
            return { success: true };
        } catch (error) {
            return { success: false, message: error.response?.data?.message || 'Login failed' };
        }
    };

    const register = async (name, email, password, role) => {
        try {
            const { data } = await API.post('/api/auth/register', { name, email, password, role });
            localStorage.setItem('user', JSON.stringify(data));
            setUser(data);
            return { success: true };
        } catch (error) {
            console.error("Registration Error from Backend:", error.response?.data || error);
            return { success: false, message: error.response?.data?.message || 'Registration failed' };
        }
    };

    const logout = () => {
        localStorage.removeItem('user');
        setUser(null);
    };

    const updateUser = (userData) => {
        const updatedUser = { ...user, ...userData };
        localStorage.setItem('user', JSON.stringify(updatedUser));
        setUser(updatedUser);
    }

    return (
        <AuthContext.Provider value={{ user, loading, login, register, logout, updateUser }}>
            {children}
        </AuthContext.Provider>
    );
};

export default AuthContext;

```

### File: frontend\context\ThemeContext.jsx
```jsx
import { createContext, useContext, useEffect, useState } from 'react'

const ThemeContext = createContext()

export function ThemeProvider({ children }) {
    const [theme, setTheme] = useState(() => {
        // Check localStorage or system preference
        if (localStorage.getItem('theme')) {
            return localStorage.getItem('theme')
        }
        return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
    })

    useEffect(() => {
        const root = document.documentElement
        if (theme === 'dark') {
            root.setAttribute('data-theme', 'dark')
        } else {
            root.removeAttribute('data-theme')
        }
        localStorage.setItem('theme', theme)
    }, [theme])

    const toggleTheme = () => {
        setTheme((prev) => (prev === 'light' ? 'dark' : 'light'))
    }

    return (
        <ThemeContext.Provider value={{ theme, toggleTheme }}>
            {children}
        </ThemeContext.Provider>
    )
}

export function useTheme() {
    return useContext(ThemeContext)
}

```

### File: frontend\index.css
```css
/* Job Tracker - Premium Global Styles */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Poppins:wght@500;600;700&display=swap');

:root {
  /* --- Typography --- */
  --font-heading: 'Poppins', sans-serif;
  --font-body: 'Inter', sans-serif;

  /* --- Light Mode (Default) --- */
  --bg-primary: #FAFAF9;
  /* Soft off-white */
  --bg-secondary: #FFFFFF;
  /* Pure white for cards */
  --bg-tertiary: #F0F4F5;
  /* Light gray/green tint for sections */

  --text-primary: #0F3D3E;
  /* Deep Teal */
  --text-secondary: #4A5568;
  /* Dark Gray */
  --text-tertiary: #8898AA;
  /* Muted */

  --accent-primary: #10B981;
  /* Brand Green */
  --accent-secondary: #0F3D3E;
  /* Deep Teal */
  --accent-hover: #059669;

  --border-color: #E2E8F0;
  --glass-bg: rgba(255, 255, 255, 0.7);
  --glass-border: rgba(255, 255, 255, 0.5);

  --shadow-sm: 0 1px 3px rgba(0, 0, 0, 0.05);
  --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.05);
  /* Softer shadow */
  --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.05);

  --radius-sm: 8px;
  --radius-md: 12px;
  --radius-lg: 16px;
  --radius-pill: 9999px;

  --grid-dot-color: #cbd5e1;
  /* Light mode dots (Slate 300) */

  /* Legacy mapping for existing components till refactor complete */
  --color-primary: var(--accent-primary);
  --color-secondary: var(--accent-secondary);
  --color-surface: var(--bg-secondary);
  --color-border: var(--border-color);
  --color-text: var(--text-primary);
  --color-text-muted: var(--text-secondary);
  --color-bg-section: var(--bg-primary);
  --sidebar-width: 260px;
}

[data-theme="dark"] {
  /* --- Dark Mode (Refined Slate Palette) --- */
  --bg-primary: #020617;
  /* Slate 950 - Deepest */
  --bg-secondary: #1e293b;
  /* Slate 800 - Standard Card */
  --bg-tertiary: #0f172a;
  /* Slate 900 - Sections */

  --text-primary: #f8fafc;
  /* Slate 50 */
  --text-secondary: #cbd5e1;
  /* Slate 300 */
  --text-tertiary: #94a3b8;
  /* Slate 400 */

  --accent-primary: #10B981;
  /* Brand Green */
  --accent-secondary: #020617;
  /* Dark contrast for accent backgrounds */
  --accent-hover: #059669;
  /* Darker Green */

  --border-color: #334155;
  /* Slate 700 - Visible borders */
  --glass-bg: rgba(2, 6, 23, 0.85);
  --glass-border: rgba(255, 255, 255, 0.1);

  --shadow-sm: 0 1px 2px rgba(0, 0, 0, 0.5);
  --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.5);
  --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.5);

  --grid-dot-color: rgba(255, 255, 255, 0.15);
  /* Dark mode dots */
}

*,
*::before,
*::after {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
}

html {
  font-size: 16px;
  scroll-behavior: smooth;
}

body {
  font-family: var(--font-body);
  background-color: var(--bg-primary);
  color: var(--text-primary);
  line-height: 1.7;
  /* Improved readability */
  min-height: 100vh;
  -webkit-font-smoothing: antialiased;
}

h1,
h2,
h3,
h4,
h5,
h6 {
  font-family: var(--font-heading);
  color: var(--text-primary);
  font-weight: 600;
  line-height: 1.3;
  letter-spacing: -0.01em;
  /* Tighter headings */
}

/* Utils */
.glass-panel {
  background: var(--glass-bg);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  border: 1px solid var(--glass-border);
}

.text-gradient {
  background: linear-gradient(135deg, var(--text-primary), var(--text-secondary));
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}

/* Reset buttons - with global improvements */
button {
  font-family: inherit;
  cursor: pointer;
  border: none;
  background: none;
  transition: transform 0.2s cubic-bezier(0.4, 0, 0.2, 1), box-shadow 0.2s ease, background-color 0.2s ease;
}

button:active {
  transform: scale(0.98);
}

button:focus-visible {
  outline: 2px solid var(--accent-primary);
  outline-offset: 2px;
}

/* Common Container */
.container {
  width: 100%;
  max-width: 1280px;
  /* Slightly wider */
  margin: 0 auto;
  padding: 0 1.5rem;
}

@media (min-width: 1024px) {
  .container {
    padding: 0 2rem;
  }
}

/* App Layout */
.app-layout {
  display: flex;
  min-height: 100vh;
  background-color: var(--bg-primary);
}

.app-main {
  flex: 1;
  display: flex;
  flex-direction: column;
  min-height: 100vh;
  min-width: 0;
  transition: margin-left 0.3s cubic-bezier(0.4, 0, 0.2, 1);
  /* Smoother bezier */
}

@media (min-width: 1024px) {
  .app-main--with-sidebar {
    margin-left: var(--sidebar-width);
  }
}

.app-content {
  flex: 1;
  display: flex;
  flex-direction: column;
}

/* ------------------------------------------------------------------ */
/* Infinite Carousel Animation (Trending Jobs)                        */
/* ------------------------------------------------------------------ */

.carousel-container {
  width: 100%;
  overflow: hidden;
  position: relative;
  /* Optional fade mask for premium feel */
  mask-image: linear-gradient(to right, transparent, black 5%, black 95%, transparent);
  -webkit-mask-image: linear-gradient(to right, transparent, black 10%, black 90%, transparent);
  padding: 2rem 0;
  /* Space for hover effects and shadow */
}

.carousel-track {
  display: flex;
  gap: 1.5rem;
  width: max-content;
  /* Move from 0 to -50% to show the full loop of duplicated items */
  /* If duplicated set is appended, we slide Left. */
  /* "Left to Right" request means visuals move to Right? */
  /* If visuals move Right, we need to animate from -50% to 0. */
  /* Let's stick to standard Marquee (Right-to-Left visual flow, i.e. items enter Right, exit Left) unless user insists on "Left to Right" direction. */
  /* User said: "Animate cards moving from LEFT -> RIGHT". */
  /* Visuals moving Left->Right means TranslateX increases. */
  /* So we start at -50% (showing right half) and move to 0 (showing left half). */
  animation: scroll-right 60s linear infinite;
  will-change: transform;
}

.carousel-track:hover {
  animation-play-state: paused;
}

@keyframes scroll-right {
  0% {
    transform: translateX(-50%);
  }

  100% {
    transform: translateX(0);
  }
}
```

### File: frontend\index.html
```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <link rel="icon" type="image/svg+xml" href="/vite.svg" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>CareerSetu | Find Your Dream Job</title>
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Manrope:wght@500;600;700&family=Poppins:wght@500;600;700&family=Open+Sans:wght@400;500;600&display=swap" rel="stylesheet" />
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/main.jsx"></script>
  </body>
</html>

```

### File: frontend\main.jsx
```jsx
import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.jsx'
import './index.css'

console.log("Starting App...");
try {
  ReactDOM.createRoot(document.getElementById('root')).render(
    <React.StrictMode>
      <App />
    </React.StrictMode>,
  )
} catch (error) {
  console.error("Error rendering App:", error);
}

```

### File: frontend\package.json
```json
{
  "name": "job-tracker-frontend",
  "private": true,
  "version": "0.0.0",
  "type": "module",
  "homepage": "https://ombiswal-04.github.io/CareerSetu.in",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview",
    "predeploy": "npm run build",
    "deploy": "gh-pages -d dist"
  },
  "dependencies": {
    "axios": "^1.13.4",
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.20.0"
  },
  "devDependencies": {
    "@vitejs/plugin-react": "^4.2.0",
    "gh-pages": "^6.3.0",
    "vite": "^5.0.0"
  }
}
```

### File: frontend\pages\AdminDashboard.jsx
```jsx
import { useState, useEffect } from 'react'
import API from '../src/api'
import { useAuth } from '../context/AuthContext'
import './Dashboard.css'
import './MyWork.css' // Reuse table styles

export default function AdminDashboard() {
    const { user } = useAuth()

    const [jobData, setJobData] = useState({
        title: '', company: '', location: '', salary: '', jobType: 'Full-time', description: '', source: 'CareerSetu', applyUrl: ''
    })
    const [postedJobs, setPostedJobs] = useState([])
    const [editJobId, setEditJobId] = useState(null)

    // Fetch jobs on mount and after posting
    const fetchJobs = async () => {
        try {
            const { data } = await API.get('/api/jobs', {
                headers: { Authorization: `Bearer ${user.token}` }
            })
            // Show all jobs (Admin + External)
            setPostedJobs(data)
        } catch (error) {
            console.error("Error fetching jobs:", error)
        }
    }

    useEffect(() => {
        fetchJobs()
    }, [])

    const handleJobSubmit = async (e) => {
        e.preventDefault()
        try {
            if (editJobId) {
                await API.put(`/api/jobs/${editJobId}`, jobData, {
                    headers: { Authorization: `Bearer ${user.token}` }
                })
                alert('Job Updated Successfully!')
                setEditJobId(null)
            } else {
                await API.post('/api/jobs', jobData, {
                    headers: { Authorization: `Bearer ${user.token}` }
                })
                alert('Job Posted Successfully!')
            }
            setJobData({ title: '', company: '', location: '', salary: '', jobType: 'Full-time', description: '', source: 'CareerSetu', applyUrl: '' })
            fetchJobs() // Refresh list
        } catch (error) {
            console.error("Error saving job:", error)
            alert('Failed to save job')
        }
    }

    const handleEditJob = (job) => {
        setJobData({
            title: job.title,
            company: job.company,
            location: job.location,
            salary: job.salary,
            jobType: job.jobType,
            description: job.description,
            source: job.source || 'CareerSetu',
            applyUrl: job.applyUrl || ''
        })
        setEditJobId(job._id)
        window.scrollTo({ top: 0, behavior: 'smooth' })
    }

    const handleCancelEdit = () => {
        setEditJobId(null)
        setJobData({ title: '', company: '', location: '', salary: '', jobType: 'Full-time', description: '', source: 'CareerSetu', applyUrl: '' })
    }

    const handleDeleteJob = async (jobId) => {
        if (window.confirm('Are you sure you want to delete this job?')) {
            try {
                await API.delete(`/api/jobs/${jobId}`, {
                    headers: { Authorization: `Bearer ${user.token}` }
                })
                alert('Job Deleted Successfully')
                fetchJobs() // Refresh list
            } catch (error) {
                console.error("Error deleting job:", error)
                alert('Failed to delete job')
            }
        }
    }

    return (
        <main className="page admin-dashboard">
            <div className="container">
                <h1 className="page__title">Admin Dashboard</h1>

                {/* Job Posting Section */}
                <section className="dashboard__section" style={{ marginBottom: '3rem' }}>
                    <h2 className="dashboard__section-title">{editJobId ? 'Edit Job' : 'Post a New Job'}</h2>
                    <form onSubmit={handleJobSubmit} className="job-form" style={{
                        display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem',
                        background: 'var(--bg-secondary)', padding: '1.5rem', borderRadius: '8px', border: '1px solid var(--border-color)'
                    }}>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                            <label>Job Title</label>
                            <input type="text" placeholder="e.g. Senior React Developer" required
                                value={jobData.title} onChange={e => setJobData({ ...jobData, title: e.target.value })}
                                style={{ padding: '0.5rem', borderRadius: '4px', border: '1px solid #ccc' }} />
                        </div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                            <label>Company</label>
                            <input type="text" placeholder="e.g. TechCorp" required
                                value={jobData.company} onChange={e => setJobData({ ...jobData, company: e.target.value })}
                                style={{ padding: '0.5rem', borderRadius: '4px', border: '1px solid #ccc' }} />
                        </div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                            <label>Location</label>
                            <input type="text" placeholder="e.g. Bangalore / Remote" required
                                value={jobData.location} onChange={e => setJobData({ ...jobData, location: e.target.value })}
                                style={{ padding: '0.5rem', borderRadius: '4px', border: '1px solid #ccc' }} />
                        </div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                            <label>Salary</label>
                            <input type="text" placeholder="e.g. ₹12L - ₹18L" required
                                value={jobData.salary} onChange={e => setJobData({ ...jobData, salary: e.target.value })}
                                style={{ padding: '0.5rem', borderRadius: '4px', border: '1px solid #ccc' }} />
                        </div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                            <label>Job Type</label>
                            <select value={jobData.jobType} onChange={e => setJobData({ ...jobData, jobType: e.target.value })}
                                style={{ padding: '0.5rem', borderRadius: '4px', border: '1px solid #ccc' }}>
                                <option value="Full-time">Full-time</option>
                                <option value="Part-time">Part-time</option>
                                <option value="Contract">Contract</option>
                                <option value="Remote">Remote</option>
                            </select>
                        </div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                            <label>Source</label>
                            <select value={jobData.source} onChange={e => setJobData({ ...jobData, source: e.target.value })}
                                style={{ padding: '0.5rem', borderRadius: '4px', border: '1px solid #ccc' }}>
                                <option value="CareerSetu">CareerSetu</option>
                                <option value="LinkedIn">LinkedIn</option>
                                <option value="Indeed">Indeed</option>
                                <option value="Naukri">Naukri</option>
                                <option value="Unstop">Unstop</option>
                                <option value="External">External</option>
                                <option value="Admin">Admin</option>
                            </select>
                        </div>
                        {jobData.source !== 'CareerSetu' && jobData.source !== 'Admin' && (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', gridColumn: '1 / -1' }}>
                                <label>Apply URL</label>
                                <input type="url" placeholder="https://..." required
                                    value={jobData.applyUrl} onChange={e => setJobData({ ...jobData, applyUrl: e.target.value })}
                                    style={{ padding: '0.5rem', borderRadius: '4px', border: '1px solid #ccc' }} />
                            </div>
                        )}
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', gridColumn: '1 / -1' }}>
                            <label>Description (Markdown supported)</label>
                            <textarea placeholder="Job description, requirements, etc..." required rows="4"
                                value={jobData.description} onChange={e => setJobData({ ...jobData, description: e.target.value })}
                                style={{ padding: '0.5rem', borderRadius: '4px', border: '1px solid #ccc' }} />
                        </div>
                        <div style={{ gridColumn: '1 / -1', display: 'flex', gap: '1rem' }}>
                            <button type="submit" style={{
                                padding: '0.75rem', background: 'var(--accent-primary)', flex: 1,
                                color: 'white', border: 'none', borderRadius: '4px', fontWeight: 'bold', cursor: 'pointer'
                            }}>
                                {editJobId ? 'Update Job' : 'Post Job'}
                            </button>
                            {editJobId && (
                                <>
                                    <button type="button" onClick={() => handleDeleteJob(editJobId)} style={{
                                        padding: '0.75rem', background: 'var(--error-color, #ef4444)', flex: 1,
                                        color: 'white', border: 'none', borderRadius: '4px', fontWeight: 'bold', cursor: 'pointer'
                                    }}>
                                        Remove Job
                                    </button>
                                    <button type="button" onClick={handleCancelEdit} style={{
                                        padding: '0.75rem', background: '#6b7280', flex: 1,
                                        color: 'white', border: 'none', borderRadius: '4px', fontWeight: 'bold', cursor: 'pointer'
                                    }}>
                                        Cancel
                                    </button>
                                </>
                            )}
                        </div>
                    </form>
                </section>

                {/* Posted Jobs List */}
                <section className="dashboard__section">
                    <h2 className="dashboard__section-title">All Jobs Management</h2>
                    {postedJobs.length === 0 ? (
                        <p style={{ color: 'var(--text-secondary)' }}>You haven't posted any jobs yet.</p>
                    ) : (
                        <div className="dashboard__table-container">
                            <table className="dashboard__table">
                                <thead>
                                    <tr>
                                        <th className="dashboard__th">Role</th>
                                        <th className="dashboard__th">Company</th>
                                        <th className="dashboard__th">Location</th>
                                        <th className="dashboard__th">Type</th>
                                        <th className="dashboard__th">Source</th>
                                        <th className="dashboard__th">Posted On / Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {postedJobs.map(job => (
                                        <tr key={job._id} className="dashboard__tr">
                                            <td className="dashboard__td" style={{ fontWeight: '500' }}>{job.title}</td>
                                            <td className="dashboard__td">{job.company}</td>
                                            <td className="dashboard__td">{job.location}</td>
                                            <td className="dashboard__td">
                                                <span className="dashboard__badge dashboard__badge--applied" style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border-color)' }}>
                                                    {job.jobType}
                                                </span>
                                            </td>
                                            <td className="dashboard__td">{job.source === 'Admin' ? 'CareerSetu' : job.source}</td>
                                            <td className="dashboard__td">
                                                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                                                    <span>{new Date(job.createdAt || Date.now()).toLocaleDateString()}</span>
                                                    <button
                                                        onClick={() => handleEditJob(job)}
                                                        style={{
                                                            background: 'var(--accent-primary)',
                                                            color: 'white',
                                                            border: 'none',
                                                            borderRadius: '4px',
                                                            padding: '0.25rem 0.75rem',
                                                            fontSize: '0.85rem',
                                                            cursor: 'pointer',
                                                            fontWeight: '500'
                                                        }}
                                                        title="Edit Job"
                                                    >
                                                        Edit
                                                    </button>
                                                </div>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                </section>
            </div>
        </main>
    )
}

```

### File: frontend\pages\Auth.css
```css
.auth {
  flex: 1;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 2rem 0 3rem;
  min-height: 60vh;
}

.auth__container {
  width: 100%;
  max-width: 420px;
}

.auth__card {
  padding: 2rem;
  background: var(--color-surface);
  border-radius: var(--radius);
  box-shadow: var(--shadow-md);
  border: 1px solid var(--color-border);
}

.auth__title {
  font-size: 1.5rem;
  font-weight: 700;
  color: var(--color-text);
  margin-bottom: 0.25rem;
}

.auth__subtitle {
  font-size: 0.9375rem;
  color: var(--color-text-muted);
  margin-bottom: 1.5rem;
}

.auth__form {
  display: flex;
  flex-direction: column;
  gap: 1.25rem;
}

.auth__field {
  display: flex;
  flex-direction: column;
  gap: 0.375rem;
}

.auth__label {
  font-size: 0.875rem;
  font-weight: 500;
  color: var(--color-text);
}

.auth__input {
  width: 100%;
  padding: 0.75rem 1rem;
  font-size: 0.9375rem;
  border: 1px solid var(--color-border);
  border-radius: var(--radius-sm);
  transition: border-color 0.2s ease, box-shadow 0.2s ease;
}

.auth__input:focus {
  outline: none;
  border-color: var(--color-primary);
  box-shadow: 0 0 0 3px var(--color-primary-light);
}

.auth__input::placeholder {
  color: var(--color-text-muted);
}

.auth__btn {
  margin-top: 0.25rem;
  padding: 0.75rem 1.5rem;
  font-size: 0.9375rem;
  font-weight: 600;
  color: rgb(15, 61, 62);
  background: var(--color-primary);
  border: none;
  border-radius: var(--radius-sm);
  transition: none;
  /* Remove transition to kill any implicit effects */
}

/* Force static background on hover to ensure "no effect" */
.auth__btn:hover {
  background: var(--color-primary);
  transform: none;
  box-shadow: none;
}


.auth__btn:active {
  transform: scale(0.98);
}

.auth__footer {
  margin-top: 1.5rem;
  font-size: 0.875rem;
  color: var(--color-text-muted);
  text-align: center;
}

.auth__link {
  font-weight: 600;
  color: var(--color-primary);
}

.auth__link:hover {
  text-decoration: underline;
}

/* Password Toggle Styles */
.auth__password-wrapper {
  position: relative;
  width: 100%;
}

.auth__password-toggle {
  position: absolute;
  right: 12px;
  top: 50%;
  transform: translateY(-50%);
  background: none;
  border: none;
  padding: 0;
  cursor: pointer;
  color: var(--color-text-muted);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 10;
}

.auth__password-toggle:hover {
  color: var(--color-text);
  background: none;
  box-shadow: none;
}
```

### File: frontend\pages\BrowseTalent.css
```css
/* Browse Mentors Page - Premium Profile Style */
.browse-talent {
    padding: 3rem 0;
    min-height: 80vh;
}

.page__title {
    font-size: 2.5rem;
    font-weight: 800;
    margin-bottom: 0.5rem;
    color: var(--text-primary);
    letter-spacing: -0.02em;
}

.page__subtitle {
    font-size: 1.1rem;
    color: var(--text-secondary);
    margin-bottom: 0.5rem;
}

.page__value-prop {
    font-size: 1rem;
    color: var(--text-tertiary);
    margin-bottom: 2.5rem;
    padding-left: 1rem;
    border-left: 3px solid var(--accent-primary);
    line-height: 1.6;
}

/* Search Bar */
.browse-talent__search {
    max-width: 700px;
    margin-bottom: 2rem;
}

.browse-talent__input {
    width: 100%;
    padding: 1rem 1.5rem;
    border-radius: var(--radius-lg);
    border: 1px solid var(--border-color);
    background: var(--bg-secondary);
    font-size: 1rem;
    box-shadow: var(--shadow-sm);
    transition: all 0.2s ease;
    color: var(--text-primary);
}

.browse-talent__input:focus {
    outline: none;
    border-color: var(--accent-primary);
    box-shadow: 0 0 0 3px rgba(16, 185, 129, 0.1);
}

/* Filters */
.browse-talent__filters {
    display: flex;
    gap: 0.75rem;
    margin-bottom: 3rem;
    flex-wrap: wrap;
}

.browse-talent__filter {
    padding: 0.6rem 1.25rem;
    border-radius: var(--radius-pill);
    border: 1px solid var(--border-color);
    background: var(--bg-secondary);
    color: var(--text-secondary);
    font-size: 0.9rem;
    font-weight: 500;
    transition: all 0.2s ease;
}

.browse-talent__filter:hover {
    border-color: var(--text-primary);
    background: var(--bg-tertiary);
    color: var(--text-primary);
}

/* Grid Layout */
.browse-talent__grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
    gap: 2rem;
}

.browse-talent__no-results {
    grid-column: 1 / -1;
    text-align: center;
    padding: 4rem 2rem;
    background: var(--bg-tertiary);
    border-radius: var(--radius-lg);
    color: var(--text-secondary);
    font-size: 1.1rem;
}

/* Mentor Card - Profile Style */
.talent-card {
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-lg);
    padding: 1.75rem;
    display: flex;
    flex-direction: column;
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    position: relative;
    overflow: hidden;
}

.talent-card:hover {
    transform: translateY(-4px);
    box-shadow: var(--shadow-lg);
    border-color: var(--accent-primary);
}

/* Top Mentor Badge */
.talent-card__badge-wrapper {
    position: absolute;
    top: 0;
    right: 0;
}

.talent-card__badge {
    background: var(--accent-primary);
    color: #fff;
    font-size: 0.7rem;
    font-weight: 700;
    padding: 0.35rem 0.75rem;
    border-bottom-left-radius: var(--radius-md);
    letter-spacing: 0.05em;
    text-transform: uppercase;
    box-shadow: var(--shadow-sm);
}

/* Header: Avatar + Info */
.talent-card__header {
    display: flex;
    gap: 1rem;
    margin-bottom: 1.5rem;
    align-items: flex-start;
}

.talent-card__avatar {
    width: 64px;
    height: 64px;
    border-radius: 50%;
    background: linear-gradient(135deg, var(--bg-tertiary), var(--border-color));
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 1.75rem;
    font-weight: 700;
    color: var(--text-primary);
    flex-shrink: 0;
    border: 2px solid var(--bg-secondary);
    box-shadow: 0 0 0 2px var(--border-color);
}

.talent-card:hover .talent-card__avatar {
    box-shadow: 0 0 0 2px var(--accent-primary);
}

.talent-card__info {
    flex: 1;
    min-width: 0;
}

.talent-card__name {
    font-size: 1.25rem;
    font-weight: 700;
    color: var(--text-primary);
    margin-bottom: 0.2rem;
    font-family: var(--font-heading);
}

.talent-card__role {
    font-size: 0.95rem;
    font-weight: 600;
    color: var(--accent-secondary);
    margin-bottom: 0.1rem;
}

.talent-card__experience {
    font-size: 0.85rem;
    color: var(--text-tertiary);
}

/* Body: Teaches & Outcome */
.talent-card__body {
    margin-bottom: 1.5rem;
    flex: 1;
}

.talent-card__label {
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-tertiary);
    font-weight: 600;
    margin-bottom: 0.75rem;
}

.talent-card__skills {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    margin-bottom: 1.25rem;
}

.talent-card__chip {
    background: var(--bg-tertiary);
    color: var(--text-secondary);
    padding: 0.35rem 0.75rem;
    border-radius: var(--radius-sm);
    font-size: 0.85rem;
    font-weight: 500;
    border: 1px solid transparent;
}

.talent-card:hover .talent-card__chip {
    border-color: var(--border-color);
    background: var(--bg-primary);
}

.talent-card__outcome {
    font-size: 0.9rem;
    color: var(--text-secondary);
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding-top: 0.75rem;
    border-top: 1px dashed var(--border-color);
}

.talent-card__check {
    color: var(--accent-primary);
    font-weight: 800;
}

/* Footer: Price & CTA */
.talent-card__footer {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-top: auto;
    gap: 1rem;
}

.talent-card__price {
    display: flex;
    flex-direction: column;
}

.talent-card__rate {
    font-size: 1.25rem;
    font-weight: 700;
    color: var(--text-primary);
    line-height: 1;
}

.talent-card__unit {
    font-size: 0.8rem;
    color: var(--text-tertiary);
    margin-top: 0.2rem;
}

.talent-card__cta {
    background: var(--text-primary);
    color: var(--bg-secondary);
    border: none;
    padding: 0.75rem 1.25rem;
    border-radius: var(--radius-md);
    font-weight: 600;
    font-size: 0.95rem;
    transition: all 0.2s ease;
    box-shadow: var(--shadow-sm);
}

.talent-card__cta:hover {
    background: var(--accent-primary);
    color: #fff;
    transform: translateY(-2px);
    box-shadow: var(--shadow-md);
}

/* Dark Mode Overrides */
[data-theme="dark"] .talent-card__cta {
    background: var(--accent-primary);
    color: var(--bg-primary);
    /* Dark text on bright button */
    font-weight: 700;
}

[data-theme="dark"] .talent-card__cta:hover {
    background: var(--accent-hover);
    color: var(--bg-primary);
}
```

### File: frontend\pages\BrowseTalent.jsx
```jsx
import { useState } from 'react'
import './BrowseTalent.css'

const MENTORS = [
  {
    id: 1,
    name: 'Priya Sharma',
    role: 'Senior Full Stack Developer',
    experience: '6+ years experience',
    location: 'Bengaluru',
    skills: ['React', 'Node.js', 'AWS', 'System Design'],
    rate: '₹1,200',
    unit: 'session',
    outcome: 'Career guidance · Code reviews',
    topMentor: true,
  },
  {
    id: 2,
    name: 'Rahul Verma',
    role: 'Data Scientist',
    experience: '8+ years experience',
    location: 'Hyderabad',
    skills: ['Python', 'Machine Learning', 'SQL'],
    rate: '₹1,500',
    unit: 'session',
    outcome: 'Live projects · Interview prep',
    topMentor: true,
  },
  {
    id: 3,
    name: 'Ananya Reddy',
    role: 'DevOps Engineer',
    experience: '5+ years experience',
    location: 'Chennai',
    skills: ['Docker', 'Kubernetes', 'CI/CD'],
    rate: '₹1,000',
    unit: 'session',
    outcome: 'Cloud Architecture · Hands-on labs',
    topMentor: true,
  },
  {
    id: 4,
    name: 'Arjun Kapoor',
    role: 'Product Designer',
    experience: '7+ years experience',
    location: 'Mumbai',
    skills: ['Figma', 'UX Research', 'Prototyping'],
    rate: '₹1,800',
    unit: 'session',
    outcome: 'Portfolio review · Design thinking',
    topMentor: true,
  },
]

export default function BrowseTalent() {
  const [search, setSearch] = useState('')

  const filteredMentors = MENTORS.filter((mentor) => {
    const term = search.toLowerCase()
    return (
      mentor.name.toLowerCase().includes(term) ||
      mentor.role.toLowerCase().includes(term) ||
      mentor.skills.some(skill => skill.toLowerCase().includes(term))
    )
  })

  return (
    <main className="page browse-talent">
      <div className="container">
        <h1 className="page__title">Top Mentors in India</h1>
        <p className="page__subtitle">Learn directly from experienced professionals in your chosen field</p>
        <p className="page__value-prop">
          Book 1-on-1 mentorship sessions, career guidance, and hands-on learning from industry experts.
        </p>

        <div className="browse-talent__search">
          <input
            type="text"
            placeholder="Search mentors by skill, role, or technology (e.g. React, Data Science)..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="browse-talent__input"
          />
        </div>

        <div className="browse-talent__filters">
          <button type="button" className="browse-talent__filter">Mentorship Area</button>
          <button type="button" className="browse-talent__filter">Skills Taught</button>
          <button type="button" className="browse-talent__filter">Mentor Location</button>
          <button type="button" className="browse-talent__filter">Session Availability</button>
        </div>

        <div className="browse-talent__grid">
          {filteredMentors.length > 0 ? (
            filteredMentors.map((mentor) => (
              <article key={mentor.id} className="talent-card">
                {mentor.topMentor && (
                  <div className="talent-card__badge-wrapper">
                    <span className="talent-card__badge">TOP MENTOR</span>
                  </div>
                )}

                <div className="talent-card__header">
                  <div className="talent-card__avatar">
                    {mentor.name?.charAt(0) || '?'}
                  </div>
                  <div className="talent-card__info">
                    <h2 className="talent-card__name">{mentor.name}</h2>
                    <p className="talent-card__role">{mentor.role}</p>
                    <p className="talent-card__experience">{mentor.experience}</p>
                  </div>
                </div>

                <div className="talent-card__body">
                  <p className="talent-card__label">Teaches:</p>
                  <div className="talent-card__skills">
                    {mentor.skills.map((skill) => (
                      <span key={skill} className="talent-card__chip">{skill}</span>
                    ))}
                  </div>
                  <div className="talent-card__outcome">
                    <span className="talent-card__check">✓</span> {mentor.outcome}
                  </div>
                </div>

                <div className="talent-card__footer">
                  <div className="talent-card__price">
                    <span className="talent-card__rate">{mentor.rate}</span>
                    <span className="talent-card__unit">/ {mentor.unit}</span>
                  </div>
                  <button type="button" className="talent-card__cta">
                    Book Mentorship
                  </button>
                </div>
              </article>
            ))
          ) : (
            <div className="browse-talent__no-results">
              <p>No mentors found matching "{search}"</p>
            </div>
          )}
        </div>
      </div>
    </main>
  )
}

```

### File: frontend\pages\CareerHelp.css
```css
.career-help {
  flex: 1;
  padding: 3rem 0;
  background: var(--bg-primary);
}

.career-help .page__title {
  margin-bottom: 0.5rem;
  font-family: var(--font-heading);
  font-size: 2rem;
  font-weight: 700;
  color: var(--text-primary);
}

.career-help__grid {
  display: grid;
  grid-template-columns: 1fr;
  gap: 1.5rem;
}

@media (min-width: 640px) {
  .career-help__grid {
    grid-template-columns: repeat(2, 1fr);
  }
}

@media (min-width: 1024px) {
  .career-help__grid {
    grid-template-columns: repeat(3, 1fr);
  }
}

.career-help__card {
  padding: 1.75rem;
  background: var(--bg-secondary);
  border-radius: var(--radius-md);
  box-shadow: var(--shadow-sm);
  border: 1px solid var(--border-color);
  transition: all 0.2s ease;
}

.career-help__card:hover {
  box-shadow: var(--shadow-md);
  transform: translateY(-3px);
  border-color: var(--accent-secondary);
}

[data-theme="dark"] .career-help__card:hover {
  border-color: var(--accent-primary);
}

.career-help__card-title {
  font-size: 1.15rem;
  font-weight: 600;
  color: var(--text-primary);
  margin-bottom: 0.75rem;
  font-family: var(--font-heading);
}

.career-help__card-desc {
  font-size: 0.95rem;
  color: var(--text-secondary);
  line-height: 1.6;
}
```

### File: frontend\pages\CareerHelp.jsx
```jsx
import './CareerHelp.css'

const HELP_CARDS = [
  { id: 1, title: 'Resume tips for Indian IT jobs', description: 'Learn how to craft a resume that stands out for Indian recruiters and ATS.' },
  { id: 2, title: 'How to crack campus placements', description: 'Prepare for aptitude tests, technical rounds, and HR interviews.' },
  { id: 3, title: 'Fresher vs experienced resume tips', description: 'Tailor your resume whether you are a fresher or experienced professional.' },
  { id: 4, title: 'Interview prep: service & product companies', description: 'Ace interviews at both IT services firms and product-based companies.' },
  { id: 5, title: 'MNC vs Startup careers in India', description: 'Understand growth, culture, and trade-offs when choosing your path.' },
]

export default function CareerHelp() {
  return (
    <main className="page career-help">
      <div className="container">
        <h1 className="page__title">Career Help</h1>
        <p className="page__subtitle">Resources to advance your career in India</p>
        <div className="career-help__grid">
          {HELP_CARDS.map((card) => (
            <article key={card.id} className="career-help__card">
              <h2 className="career-help__card-title">{card.title}</h2>
              <p className="career-help__card-desc">{card.description}</p>
            </article>
          ))}
        </div>
      </div>
    </main>
  )
}

```

### File: frontend\pages\Dashboard.css
```css
/* Dashboard Layout */
.dashboard {
    background-color: var(--bg-secondary);
    min-height: 100vh;
    padding: 2rem 0;
}

.dashboard__title {
    font-size: 2rem;
    font-weight: 700;
    color: var(--text-primary);
    margin-bottom: 0.5rem;
}

.dashboard__subtitle {
    color: var(--text-secondary);
    font-size: 1rem;
    margin-bottom: 2rem;
}

/* Stats Cards */
.dashboard__stats {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
    gap: 1.5rem;
    margin-bottom: 2.5rem;
}

.dashboard__stat-card {
    background: var(--bg-primary);
    padding: 1.5rem;
    border-radius: 12px;
    border: 1px solid var(--border-color);
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
}

.dashboard__stat-label {
    color: var(--text-secondary);
    font-size: 0.9rem;
    font-weight: 500;
}

.dashboard__stat-value {
    color: var(--text-primary);
    font-size: 2rem;
    font-weight: 700;
}

.stat-detail {
    font-size: 0.85rem;
    color: var(--accent-primary);
    margin-top: auto;
}

/* Sections */
.dashboard__section-title {
    font-size: 1.25rem;
    font-weight: 600;
    color: var(--text-primary);
    margin-bottom: 1rem;
}

/* Tables */
.dashboard__table-container {
    background: var(--bg-primary);
    border-radius: 12px;
    border: 1px solid var(--border-color);
    overflow: hidden;
    overflow-x: auto;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
}

.dashboard__table {
    width: 100%;
    border-collapse: collapse;
    text-align: left;
    min-width: 800px;
    /* Force scroll on small screens */
}

.dashboard__th {
    background: var(--bg-tertiary);
    color: var(--text-secondary);
    font-weight: 600;
    font-size: 0.9rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    padding: 1rem 1.5rem;
    border-bottom: 1px solid var(--border-color);
}

.dashboard__td {
    padding: 1rem 1.5rem;
    color: var(--text-primary);
    border-bottom: 1px solid var(--border-color);
    vertical-align: middle;
}

.dashboard__tr:last-child .dashboard__td {
    border-bottom: none;
}

.dashboard__tr:hover {
    background: var(--bg-secondary);
}

/* Badges */
.dashboard__status-badge,
.dashboard__badge {
    display: inline-flex;
    align-items: center;
    padding: 0.25rem 0.75rem;
    border-radius: 9999px;
    font-size: 0.85rem;
    font-weight: 500;
    text-transform: capitalize;
}

/* Status variants */
.status-applied,
.dashboard__badge--applied {
    background: rgba(59, 130, 246, 0.1);
    color: #3b82f6;
}

.status-interview,
.dashboard__badge--interview {
    background: rgba(245, 158, 11, 0.1);
    color: #f59e0b;
}

.status-offer,
.status-accepted,
.dashboard__badge--offer {
    background: rgba(16, 185, 129, 0.1);
    color: #10b981;
}

.status-rejected,
.dashboard__badge--rejected {
    background: rgba(239, 68, 68, 0.1);
    color: #ef4444;
}

/* Empty State */
.dashboard__empty {
    text-align: center;
    padding: 4rem 2rem;
    background: var(--bg-primary);
    border-radius: 12px;
    border: 1px solid var(--border-color);
}

.dashboard__empty-title {
    font-size: 1.25rem;
    color: var(--text-primary);
    margin-bottom: 0.5rem;
}

.dashboard__empty p {
    color: var(--text-secondary);
    margin-bottom: 1.5rem;
}

.dashboard__empty-btn {
    display: inline-block;
    background: var(--accent-primary);
    color: #fff;
    padding: 0.75rem 1.5rem;
    border-radius: 6px;
    text-decoration: none;
    font-weight: 500;
    transition: opacity 0.2s;
}

.dashboard__empty-btn:hover {
    opacity: 0.9;
}
```

### File: frontend\pages\Hire.css
```css
/* Hire.css */

.candidates-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
    gap: 1.5rem;
    margin-top: 1.5rem;
}

.candidate-card {
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    padding: 1.5rem;
    box-shadow: var(--shadow-sm);
    transition: transform 0.2s, box-shadow 0.2s;
    display: flex;
    flex-direction: column;
    gap: 1rem;
}

.candidate-card:hover {
    transform: translateY(-4px);
    box-shadow: var(--shadow-md);
    border-color: var(--color-primary);
}

.candidate-info {
    border-bottom: 1px solid var(--border-color);
    padding-bottom: 1rem;
    margin-bottom: 0.5rem;
}

.candidate-name {
    font-size: 1.1rem;
    font-weight: 700;
    color: var(--text-primary);
    margin-bottom: 0.25rem;
}

.candidate-job {
    font-size: 0.9rem;
    color: var(--text-secondary);
    margin-bottom: 0.25rem;
}

.candidate-meta {
    font-size: 0.85rem;
    color: var(--text-tertiary);
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.candidate-actions {
    display: flex;
    gap: 0.5rem;
    flex-wrap: wrap;
    margin-top: auto;
}

.btn-action {
    flex: 1;
    padding: 0.5rem;
    border: none;
    border-radius: 6px;
    font-size: 0.85rem;
    font-weight: 600;
    cursor: pointer;
    transition: filter 0.2s;
}

.btn-accept {
    background: #10b981;
    color: white;
}

.btn-reject {
    background: #ef4444;
    color: white;
}

.btn-schedule {
    background: #3b82f6;
    color: white;
    flex: 100%;
}

.btn-action:hover {
    filter: brightness(1.1);
}
```

### File: frontend\pages\Hire.jsx
```jsx
import { useState, useEffect } from 'react'
import API from '../src/api'
import { useAuth } from '../context/AuthContext'
import './Dashboard.css'
import './Hire.css'

export default function Hire() {
    const [applications, setApplications] = useState([])
    const { user } = useAuth()
    const [loading, setLoading] = useState(true)
    const [scheduleData, setScheduleData] = useState({ id: null, date: '', time: '' })

    const fetchApplications = async () => {
        try {
            const { data } = await API.get('/api/applications/admin/all', {
                headers: { Authorization: `Bearer ${user.token}` }
            })
            setApplications(data)
        } catch (error) {
            console.error("Error fetching applications:", error)
        } finally {
            setLoading(false)
        }
    }

    useEffect(() => {
        if (user) fetchApplications()
    }, [user])

    const handleStatusUpdate = async (id, status) => {
        try {
            await API.put(`/api/applications/admin/${id}/status`, { status }, {
                headers: { Authorization: `Bearer ${user.token}` }
            })
            fetchApplications()
        } catch (error) {
            console.error("Error updating status:", error)
        }
    }

    const handleScheduleSubmit = async (e) => {
        e.preventDefault()
        try {
            await API.put(`/api/applications/admin/${scheduleData.id}/schedule`, {
                interviewDate: scheduleData.date,
                interviewTime: scheduleData.time
            }, {
                headers: { Authorization: `Bearer ${user.token}` }
            })
            setScheduleData({ id: null, date: '', time: '' })
            fetchApplications()
        } catch (error) {
            console.error("Error scheduling:", error)
        }
    }

    if (loading) return <div className="container">Loading...</div>

    return (
        <main className="page admin-dashboard">
            <div className="container">
                <h1 className="page__title">Hire Candidates</h1>
                <p className="dashboard__subtitle">Manage job applications and interviews</p>

                <div className="applications-list">
                    {applications.length === 0 ? (
                        <p>No applications received yet.</p>
                    ) : (
                        <div className="candidates-grid">
                            {applications.map(app => (
                                <div key={app._id} className="candidate-card">
                                    <div className="candidate-info">
                                        <div className="candidate-name">{app.userId.name}</div>
                                        <div className="candidate-job">Applied for: <strong>{app.jobId.title}</strong></div>
                                        <div className="candidate-meta">{app.userId.email}</div>
                                        <div className="candidate-resume-status" style={{ marginTop: '0.75rem' }}>
                                            {app.userId.resumeUrl ? (
                                                <a
                                                    href={app.userId.resumeUrl}
                                                    target="_blank"
                                                    rel="noopener noreferrer"
                                                    className="btn-action"
                                                    style={{
                                                        display: 'inline-flex',
                                                        alignItems: 'center',
                                                        gap: '0.5rem',
                                                        background: 'var(--color-primary)',
                                                        color: 'white',
                                                        padding: '0.5rem 1rem',
                                                        borderRadius: '6px',
                                                        textDecoration: 'none',
                                                        fontSize: '0.85rem'
                                                    }}
                                                >
                                                    <span>📄 View Resume</span>
                                                </a>
                                            ) : (
                                                <span style={{
                                                    color: 'var(--text-tertiary)',
                                                    fontSize: '0.85rem',
                                                    fontStyle: 'italic',
                                                    display: 'flex',
                                                    alignItems: 'center',
                                                    gap: '0.5rem'
                                                }}>
                                                    ⚠️ No resume uploaded
                                                </span>
                                            )}
                                        </div>
                                    </div>

                                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                        <span className={`dashboard__status-badge status-${app.status}`}>
                                            {app.status}
                                        </span>
                                        <span style={{ fontSize: '0.8rem', color: '#888' }}>
                                            {new Date(app.createdAt || Date.now()).toLocaleDateString()}
                                        </span>
                                    </div>

                                    <div className="candidate-actions">
                                        {app.status === 'applied' && (
                                            <>
                                                <button className="btn-action btn-accept" onClick={() => handleStatusUpdate(app._id, 'accepted')}>Accept</button>
                                                <button className="btn-action btn-reject" onClick={() => handleStatusUpdate(app._id, 'rejected')}>Reject</button>
                                                <button className="btn-action btn-schedule" onClick={() => setScheduleData({ ...scheduleData, id: app._id })}>Schedule Interview</button>
                                            </>
                                        )}
                                        {app.status === 'interview' && (
                                            <div style={{ width: '100%', fontSize: '0.85rem', background: '#f3f4f6', padding: '0.5rem', borderRadius: '4px' }}>
                                                <strong>Interview:</strong> {app.interviewDate} @ {app.interviewTime}
                                            </div>
                                        )}
                                    </div>

                                    {scheduleData.id === app._id && (
                                        <form onSubmit={handleScheduleSubmit} style={{ marginTop: '10px', padding: '10px', background: '#f9fafb', borderRadius: '6px' }}>
                                            <div style={{ display: 'grid', gap: '0.5rem' }}>
                                                <input type="date" required value={scheduleData.date} onChange={(e) => setScheduleData({ ...scheduleData, date: e.target.value })} style={{ width: '100%', padding: '0.5rem' }} />
                                                <input type="time" required value={scheduleData.time} onChange={(e) => setScheduleData({ ...scheduleData, time: e.target.value })} style={{ width: '100%', padding: '0.5rem' }} />
                                                <button type="submit" className="btn-action btn-schedule">Confirm</button>
                                                <button type="button" onClick={() => setScheduleData({ id: null, date: '', time: '' })} style={{ width: '100%', padding: '0.5rem', background: 'none', border: 'none', cursor: 'pointer', fontSize: '0.85rem' }}>Cancel</button>
                                            </div>
                                        </form>
                                    )}
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            </div>
        </main>
    )
}

```

### File: frontend\pages\Home.css
```css
.visually-hidden {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}

.home {
  flex: 1;
}

/* Hero - centered, large headline, grid/pattern background */
.hero {
  position: relative;
  padding: 6rem 0 8rem;
  /* Increased vertical breathing room */
  background: var(--bg-primary);
  overflow: hidden;
}

.hero::before {
  content: '';
  position: absolute;
  inset: 0;
  /* More subtle dot pattern */
  background-image: radial-gradient(var(--grid-dot-color) 1px, transparent 1px);
  background-size: 32px 32px;
  /* Opacity handled by color variable or set to 1 if using translucent colors */
  opacity: 1;
  /* Subtle visibility */
  pointer-events: none;
  mask-image: radial-gradient(circle at center, black 40%, transparent 80%);
  -webkit-mask-image: radial-gradient(circle at center, black 40%, transparent 80%);
}

.hero__container {
  position: relative;
  display: flex;
  flex-direction: column;
  align-items: center;
  text-align: center;
  gap: 2rem;
  /* Increased gap */
  z-index: 1;
}

.hero__title {
  font-family: var(--font-heading);
  font-size: 2.75rem;
  font-weight: 700;
  color: var(--text-primary);
  line-height: 1.1;
  letter-spacing: -0.04em;
  /* Tighter for large text */
  max-width: 800px;
}

.hero__title span {
  color: var(--accent-secondary);
  background: linear-gradient(135deg, var(--accent-secondary), var(--text-primary));
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}

.hero__subtext {
  font-family: var(--font-body);
  font-size: 1.1rem;
  color: var(--text-secondary);
  max-width: 540px;
  line-height: 1.6;
}

.hero__search {
  width: 100%;
  max-width: 720px;
  margin-top: 1rem;
}

.hero__search-row {
  display: flex;
  flex-direction: column;
  gap: 1rem;
  padding: 0.75rem;
  background: var(--bg-secondary);
  border-radius: var(--radius-md);
  box-shadow: var(--shadow-lg);
  border: 1px solid rgb(15, 61, 62);
}

.hero__input {
  width: 100%;
  padding: 1rem 1.25rem;
  font-size: 1rem;
  border: 1px solid transparent;
  background: var(--bg-primary);
  border-radius: var(--radius-sm);
  transition: all 0.2s ease;
  color: var(--text-primary);
}

.hero__input:focus {
  outline: none;
  background: var(--bg-secondary);
  border-color: var(--accent-secondary);
  box-shadow: 0 0 0 2px rgba(15, 61, 62, 0.05);
}

.hero__input::placeholder {
  color: var(--text-tertiary);
}

.hero__btn {
  padding: 1rem 2rem;
  font-size: 1rem;
  font-weight: 600;
  color: var(--bg-secondary);
  /* Text usually white/light */
  background: var(--text-primary);
  /* Dark button */
  border: none;
  border-radius: var(--radius-sm);
  transition: all 0.2s ease;
  box-shadow: var(--shadow-md);
}

.hero__btn:hover {
  background: var(--accent-primary);
  color: var(--text-primary);
  transform: translateY(-1px);
}

.hero__btn:active {
  transform: scale(0.98);
}

@media (min-width: 640px) {
  .hero__search-row {
    flex-direction: row;
    padding: 0.75rem;
  }

  .hero__input {
    flex: 1;
    min-width: 250px;
  }

  .hero__btn {
    flex-shrink: 0;
  }
}

@media (min-width: 768px) {
  .hero {
    padding: 7rem 0 9rem;
  }

  .hero__title {
    font-size: 4rem;
    /* Larger desktop title */
  }

  .hero__subtext {
    font-size: 1.2rem;
  }
}

/* Mobile optimizations */
@media (max-width: 639px) {
  .hero {
    padding: 3rem 0 4rem;
  }

  .hero__title {
    font-size: 2rem;
  }

  .hero__search-row {
    gap: 0.75rem;
  }

  .hero__btn {
    width: 100%;
  }
}

/* Section titles */
.section__title {
  font-family: var(--font-heading);
  font-size: 1.75rem;
  font-weight: 700;
  color: var(--text-primary);
  margin-bottom: 2.5rem;
  text-align: center;
}

/* Trending Jobs */
.trending {
  padding: 4rem 0;
  background: var(--bg-tertiary);
}

.trending__grid {
  display: grid;
  gap: 1.5rem;
}

@media (min-width: 640px) {
  .trending__grid {
    grid-template-columns: repeat(2, 1fr);
  }
}

@media (min-width: 1024px) {
  .trending__grid {
    grid-template-columns: repeat(4, 1fr);
  }
}

/* Categories */
.categories {
  padding: 4rem 0 5rem;
  background: var(--bg-primary);
}

.categories__grid {
  display: flex;
  flex-wrap: wrap;
  gap: 1.25rem;
  justify-content: center;
}

.category-card {
  display: flex;
  flex-direction: row;
  align-items: center;
  gap: 1rem;
  padding: 1.25rem 1.5rem;
  background: var(--bg-secondary);
  border-radius: var(--radius-md);
  border: 1px solid var(--border-color);
  box-shadow: var(--shadow-sm);
  /* transition: all 0.2s ease;  Removed transition */
  min-width: 160px;
  cursor: pointer;
  text-align: left;
  font: inherit;
}

/* Hover effects removed as requested */
/* .category-card:not(.category-card--active):hover { ... } */

/* Prevent sticky focus on click - use focus-visible for keyboard users */
.category-card:focus {
  outline: none;
  border-color: var(--border-color);
}

.category-card:focus-visible {
  outline: 2px solid var(--accent-primary);
  outline-offset: 2px;
  border-color: var(--accent-primary);
}

.category-card--active {
  background: var(--bg-secondary);
  border-color: var(--border-color);
  /* Reset to default border */
  box-shadow: var(--shadow-sm);
  /* Reset to default shadow */
}

.category-card--active .category-card__icon {
  background: var(--bg-tertiary);
  color: var(--accent-primary);
}

/* Dark mode active state tweak */
/* Dark mode active state tweak - keep consistent outline style */
[data-theme="dark"] .category-card--active {
  background: var(--bg-secondary);
  border-color: var(--border-color);
  color: var(--text-primary);
}

[data-theme="dark"] .category-card--active .category-card__icon {
  background: var(--bg-tertiary);
  color: var(--accent-primary);
}

[data-theme="dark"] .category-card--active .category-card__name,
[data-theme="dark"] .category-card--active .category-card__count {
  color: inherit;
}


.category-card__icon {
  width: 3rem;
  height: 3rem;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--bg-tertiary);
  color: var(--text-primary);
  font-size: 1.5rem;
  border-radius: 50%;
  /* transition: all 0.2s ease; Removed transition */
  flex-shrink: 0;
}

.category-card__content {
  display: flex;
  flex-direction: column;
  gap: 0.125rem;
}

.category-card__name {
  font-family: var(--font-heading);
  font-size: 1rem;
  font-weight: 600;
  color: inherit;
  /* Inherits from card color */
}

/* Default state colors */
.category-card:not(.category-card--active) .category-card__name {
  color: var(--text-primary);
}

.category-card__count {
  font-size: 0.8rem;
  color: var(--text-secondary);
}

.category-card--active .category-card__count {
  color: var(--text-secondary);
}

@media (min-width: 640px) {
  .categories__grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  }
}
```

### File: frontend\pages\Home.jsx
```jsx
import { useState } from 'react'
import JobCard from '../components/JobCard'
import './Home.css'

const TRENDING_JOBS = [
  {
    id: 1,
    title: 'Frontend Developer (React)',
    company: 'Flipkart',
    location: 'Bengaluru',
    type: 'Hybrid',
    salary: '₹12–18 LPA',
  },
  {
    id: 2,
    title: 'UI/UX Designer',
    company: 'Zoho',
    location: 'Chennai',
    type: 'Full-time',
    salary: '₹6–10 LPA',
  },
  {
    id: 3,
    title: 'Full Stack Developer (MERN)',
    company: 'Razorpay',
    location: 'Bengaluru',
    type: 'Remote',
    salary: '₹15–22 LPA',
  },
  {
    id: 4,
    title: 'Data Analyst',
    company: 'Accenture India',
    location: 'Hyderabad',
    type: 'Full-time',
    salary: '₹8–12 LPA',
  },
  {
    id: 5,
    title: 'Product Manager',
    company: 'Swiggy',
    location: 'Bengaluru',
    type: 'Hybrid',
    salary: '₹25–35 LPA',
  },
  {
    id: 6,
    title: 'DevOps Engineer',
    company: 'TCS',
    location: 'Mumbai',
    type: 'Full-time',
    salary: '₹6–9 LPA',
  },
  {
    id: 7,
    title: 'Mobile Developer (Flutter)',
    company: 'Zomato',
    location: 'Gurugram',
    type: 'Remote',
    salary: '₹18–24 LPA',
  },
  {
    id: 8,
    title: 'Data Scientist',
    company: 'Fractal',
    location: 'Mumbai',
    type: 'Hybrid',
    salary: '₹14–20 LPA',
  },
  // Duplicates for seamless loop
  {
    id: '1-dup',
    title: 'Frontend Developer (React)',
    company: 'Flipkart',
    location: 'Bengaluru',
    type: 'Hybrid',
    salary: '₹12–18 LPA',
  },
  {
    id: '2-dup',
    title: 'UI/UX Designer',
    company: 'Zoho',
    location: 'Chennai',
    type: 'Full-time',
    salary: '₹6–10 LPA',
  },
  {
    id: '3-dup',
    title: 'Full Stack Developer (MERN)',
    company: 'Razorpay',
    location: 'Bengaluru',
    type: 'Remote',
    salary: '₹15–22 LPA',
  },
  {
    id: '4-dup',
    title: 'Data Analyst',
    company: 'Accenture India',
    location: 'Hyderabad',
    type: 'Full-time',
    salary: '₹8–12 LPA',
  },
  {
    id: '5-dup',
    title: 'Product Manager',
    company: 'Swiggy',
    location: 'Bengaluru',
    type: 'Hybrid',
    salary: '₹25–35 LPA',
  },
  {
    id: '6-dup',
    title: 'DevOps Engineer',
    company: 'TCS',
    location: 'Mumbai',
    type: 'Full-time',
    salary: '₹6–9 LPA',
  },
  {
    id: '7-dup',
    title: 'Mobile Developer (Flutter)',
    company: 'Zomato',
    location: 'Gurugram',
    type: 'Remote',
    salary: '₹18–24 LPA',
  },
  {
    id: '8-dup',
    title: 'Data Scientist',
    company: 'Fractal',
    location: 'Mumbai',
    type: 'Hybrid',
    salary: '₹14–20 LPA',
  },
]

const CATEGORIES = [
  { name: 'Development', icon: '💻', count: '2,340' },
  { name: 'UI/UX', icon: '🎨', count: '890' },
  { name: 'Marketing', icon: '📢', count: '1,120' },
  { name: 'Business', icon: '📊', count: '756' },
  { name: 'Finance', icon: '💰', count: '445' },
]

export default function Home() {
  const [keyword, setKeyword] = useState('')
  const [location, setLocation] = useState('')
  const [activeCategory, setActiveCategory] = useState('Development')

  const handleSearch = (e) => {
    e.preventDefault()
    // UI only - no API
  }

  return (
    <main className="home">
      <section className="hero">
        <div className="hero__container container">
          <h1 className="hero__title">Get The Right Job You Deserve</h1>
          <p className="hero__subtext">
            Find jobs and internships across top Indian companies. Connecting Indian talent with the right opportunities.
          </p>
          <form className="hero__search" onSubmit={handleSearch}>
            <div className="hero__search-row">
              <label htmlFor="keyword" className="visually-hidden">
                Job title or keyword
              </label>
              <input
                id="keyword"
                type="text"
                placeholder="Job title or keyword"
                value={keyword}
                onChange={(e) => setKeyword(e.target.value)}
                className="hero__input"
              />
              <label htmlFor="location" className="visually-hidden">
                Location
              </label>
              <input
                id="location"
                type="text"
                placeholder="City (e.g. Bengaluru, Mumbai)"
                value={location}
                onChange={(e) => setLocation(e.target.value)}
                className="hero__input"
              />
              <button type="submit" className="hero__btn">
                Search
              </button>
            </div>
          </form>
        </div>
      </section>

      <section className="trending" id="jobs">
        <div className="container">
          <h2 className="section__title">Trending Jobs in India</h2>
          <div className="carousel-container">
            <div className="carousel-track">
              {TRENDING_JOBS.map((job) => (
                <JobCard key={job.id} job={job} />
              ))}
            </div>
          </div>
        </div>
      </section>

      <section className="categories">
        <div className="container">
          <h2 className="section__title">Browse by Category</h2>
          <div className="categories__grid">
            {CATEGORIES.map((cat) => (
              <button
                key={cat.name}
                type="button"
                className={`category-card ${activeCategory === cat.name ? 'category-card--active' : ''}`}
                onClick={() => setActiveCategory(cat.name)}
              >
                <span className="category-card__icon" aria-hidden>
                  {cat.icon}
                </span>
                <div className="category-card__content">
                  <h3 className="category-card__name">{cat.name}</h3>
                  <p className="category-card__count">{cat.count} jobs</p>
                </div>
              </button>
            ))}
          </div>
        </div>
      </section>
    </main>
  )
}

```

### File: frontend\pages\Jobs.css
```css
.page {
    flex: 1;
    padding: 3rem 0 5rem;
    background: var(--bg-primary);
}

.page__title {
    font-family: var(--font-heading);
    font-size: 2rem;
    font-weight: 700;
    color: var(--text-primary);
    margin-bottom: 0.5rem;
}

.page__subtitle {
    font-size: 1.05rem;
    color: var(--text-secondary);
    margin-bottom: 2rem;
    max-width: 600px;
}

.jobs__list {
    display: flex;
    flex-direction: column;
    gap: 1.25rem;
}

.jobs__card {
    display: flex;
    align-items: center;
    gap: 1.25rem;
    padding: 1.5rem;
    background: var(--bg-secondary);
    border-radius: var(--radius-md);
    box-shadow: var(--shadow-sm);
    border: 1px solid var(--border-color);
    transition: all 0.2s ease;
}

.jobs__card:hover {
    box-shadow: var(--shadow-md);
    border-color: var(--accent-secondary);
    transform: translateY(-2px);
}

[data-theme="dark"] .jobs__card:hover {
    border-color: var(--accent-primary);
}

.jobs__card-logo {
    width: 56px;
    height: 56px;
    flex-shrink: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--bg-tertiary);
    color: var(--text-primary);
    font-size: 1.25rem;
    font-weight: 700;
    border-radius: var(--radius-sm);
}

.jobs__card-body {
    flex: 1;
    min-width: 0;
}

.jobs__card-title {
    font-size: 1.1rem;
    font-weight: 600;
    color: var(--text-primary);
    margin-bottom: 0.25rem;
}

.jobs__card-company {
    font-size: 0.95rem;
    color: var(--text-secondary);
    font-weight: 500;
}

.jobs__card-location {
    font-size: 0.875rem;
    color: var(--text-tertiary);
    margin-top: 0.25rem;
}

.jobs__badge {
    display: inline-block;
    padding: 0.35rem 0.85rem;
    font-size: 0.8rem;
    font-weight: 600;
    border-radius: var(--radius-pill);
    text-transform: uppercase;
    letter-spacing: 0.02em;
}

.jobs__badge--applied {
    background: var(--bg-tertiary);
    color: var(--text-primary);
    border: 1px solid var(--border-color);
}

.jobs__badge--interview {
    background: rgba(245, 158, 11, 0.1);
    color: #d97706;
    border: 1px solid rgba(245, 158, 11, 0.2);
}

.jobs__badge--offer {
    background: rgba(16, 185, 129, 0.1);
    color: #059669;
    border: 1px solid rgba(16, 185, 129, 0.2);
}

.jobs__badge--saved {
    background: var(--bg-primary);
    color: var(--text-tertiary);
    border: 1px solid var(--border-color);
}

@media (min-width: 768px) {
    .page__title {
        font-size: 2.25rem;
    }

    .jobs__card {
        padding: 1.75rem;
    }
}
```

### File: frontend\pages\Jobs.jsx
```jsx
import { useState, useEffect } from 'react'
import API from '../src/api'
import JobCard from '../components/JobCard'
import { useAuth } from '../context/AuthContext'
import './Jobs.css'

export default function Jobs() {
  const [jobs, setJobs] = useState([])
  const [appliedJobIds, setAppliedJobIds] = useState(new Set())
  const { user } = useAuth()
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const fetchData = async () => {
      try {
        const jobsRes = await API.get('/api/jobs', {
          headers: user ? { Authorization: `Bearer ${user.token}` } : {}
        })
        setJobs(jobsRes.data)

        if (user) {
          const appsRes = await API.get('/api/applications/my-work', {
            headers: { Authorization: `Bearer ${user.token}` }
          })
          const ids = new Set(appsRes.data.map(app => app.jobId._id || app.jobId))
          setAppliedJobIds(ids)
        }
      } catch (error) {
        console.error("Error fetching data:", error)
      } finally {
        setLoading(false)
      }
    }

    fetchData()
  }, [user])

  const handleApply = async (jobId) => {
    if (!user) {
      alert('Please login to apply')
      return
    }

    if (!user.resumeUrl) {
      alert('You must upload a resume before applying. Please go to "Career" section to upload your resume.')
      return
    }
    try {
      await API.post(`/api/applications/${jobId}`, {}, {
        headers: { Authorization: `Bearer ${user.token}` }
      })
      setAppliedJobIds(prev => new Set(prev).add(jobId))
    } catch (error) {
      console.error("Error applying:", error)
      alert(error.response?.data?.message || "Failed to apply")
    }
  }

  if (loading) return <div className="container">Loading jobs...</div>

  return (
    <main className="page jobs">
      <div className="container">
        <h1 className="page__title">Jobs in India</h1>
        <p className="page__subtitle">Find your dream job today</p>
        <div className="jobs__list">
          {jobs.map((job) => (
            <JobCard
              key={job._id}
              job={job}
              isApplied={appliedJobIds.has(job._id)}
              onApply={handleApply}
            />
          ))}
          {jobs.length === 0 && <p>No jobs found.</p>}
        </div>
      </div>
    </main>
  )
}

```

### File: frontend\pages\Login.jsx
```jsx
import { useState, useEffect } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import './Auth.css'

export default function Login() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const { login, user } = useAuth()
  const navigate = useNavigate()
  const [error, setError] = useState('')

  useEffect(() => {
    if (user) {
      if (user.role === 'admin') {
        navigate('/admin')
      } else {
        navigate('/jobs')
      }
    }
  }, [user, navigate])

  const handleSubmit = async (e) => {
    e.preventDefault()
    const result = await login(email, password)
    if (!result.success) {
      setError(result.message)
    }
  }

  return (
    <main className="auth">
      <div className="auth__container container">
        <div className="auth__card">
          <h1 className="auth__title">Login</h1>
          <p className="auth__subtitle">Sign in to your account</p>
          {error && <p className="error-message">{error}</p>}
          <form className="auth__form" onSubmit={handleSubmit}>
            <div className="auth__field">
              <label htmlFor="login-email" className="auth__label">
                Email
              </label>
              <input
                id="login-email"
                type="email"
                placeholder="you@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="auth__input"
                required
              />
            </div>
            <div className="auth__field">
              <label htmlFor="login-password" className="auth__label">
                Password
              </label>
              <div className="auth__password-wrapper">
                <input
                  id="login-password"
                  type={showPassword ? "text" : "password"}
                  placeholder=""
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="auth__input"
                  required
                />
                <button
                  type="button"
                  className="auth__password-toggle"
                  onClick={() => setShowPassword(!showPassword)}
                  aria-label={showPassword ? "Hide password" : "Show password"}
                >
                  {showPassword ? (
                    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
                      <line x1="1" y1="1" x2="23" y2="23"></line>
                    </svg>
                  ) : (
                    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                      <circle cx="12" cy="12" r="3"></circle>
                    </svg>
                  )}
                </button>
              </div>
            </div>
            <button type="submit" className="auth__btn">
              Login
            </button>
          </form>
          <p className="auth__footer">
            Don&apos;t have an account?{' '}
            <Link to="/register" className="auth__link">
              Register
            </Link>
          </p>
        </div>
      </div>
    </main>
  )
}

```

### File: frontend\pages\MyJobs.css
```css
.my-jobs {
    background-color: var(--bg-secondary);
    /* Light background for contrast with white cards */
    min-height: 80vh;
    padding: 3rem 1rem;
}

.my-jobs__header {
    text-align: center;
    max-width: 800px;
    margin: 0 auto 3rem;
}

.my-jobs__title {
    font-size: 2.5rem;
    font-weight: 700;
    color: var(--text-primary);
    margin-bottom: 0.5rem;
    font-family: var(--font-heading);
}

.my-jobs__grid {
    display: grid;
    gap: 2rem;
    max-width: 900px;
    margin: 0 auto;
}

/* Card Styling */
.job-card-section {
    background: var(--bg-primary);
    /* White on light mode */
    border-radius: 12px;
    padding: 2rem;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05), 0 2px 4px -1px rgba(0, 0, 0, 0.03);
    border: 1px solid var(--border-color);
    transition: transform 0.2s ease, box-shadow 0.2s ease;
}

.job-card-section:hover {
    box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.05), 0 4px 6px -2px rgba(0, 0, 0, 0.025);
}

.job-card__header {
    margin-bottom: 1.5rem;
    padding-bottom: 1rem;
    border-bottom: 1px solid var(--border-color);
}

.job-card__title {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    font-size: 1.35rem;
    font-weight: 600;
    color: var(--text-primary);
    margin-bottom: 0.5rem;
}

.job-card__icon {
    font-size: 1.5rem;
}

.job-card__subtext {
    font-size: 0.95rem;
    color: var(--text-secondary);
}

/* Resume Upload Form */
.resume-upload-form {
    display: flex;
    flex-direction: column;
    gap: 1rem;
}

@media (min-width: 640px) {
    .resume-upload-form {
        flex-direction: row;
        align-items: center;
    }
}

.file-input {
    flex: 1;
    padding: 0.75rem;
    border: 1px dashed var(--border-color);
    border-radius: 8px;
    background: var(--bg-secondary);
    font-size: 0.9rem;
    color: var(--text-secondary);
    cursor: pointer;
}

.file-input:hover {
    border-color: var(--accent-primary);
    background: var(--bg-tertiary);
}

.btn-upload {
    background-color: #10b981;
    /* Success Green */
    color: white;
    padding: 0.75rem 1.5rem;
    border-radius: 8px;
    font-weight: 600;
    border: none;
    cursor: pointer;
    transition: all 0.2s;
    white-space: nowrap;
}

.btn-upload:hover {
    background-color: #059669;
    transform: translateY(-1px);
    box-shadow: 0 2px 4px rgba(16, 185, 129, 0.2);
}

.btn-upload:disabled {
    opacity: 0.7;
    cursor: not-allowed;
}

/* Skills Input */
.skills-input-group {
    position: relative;
    display: flex;
    flex-direction: column;
    gap: 1rem;
}

@media (min-width: 640px) {
    .skills-input-group {
        flex-direction: row;
    }
}

.modern-input {
    flex: 1;
    padding: 0.85rem 1rem;
    border: 1px solid var(--border-color);
    border-radius: 8px;
    font-size: 1rem;
    background: var(--bg-primary);
    color: var(--text-primary);
    transition: border-color 0.2s, box-shadow 0.2s;
}

.modern-input:focus {
    outline: none;
    border-color: var(--accent-primary);
    box-shadow: 0 0 0 3px rgba(var(--accent-primary-rgb), 0.1);
}

.btn-find {
    background-color: var(--accent-primary);
    color: var(--accent-secondary);
    padding: 0.85rem 2rem;
    border-radius: 8px;
    font-weight: 600;
    border: none;
    cursor: pointer;
    transition: all 0.2s;
}

.btn-find:hover {
    background-color: var(--accent-hover);
    transform: translateY(-1px);
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
}

.helper-text {
    font-size: 0.85rem;
    color: var(--text-tertiary);
    margin-top: 0.5rem;
}

.status-message {
    margin-top: 1rem;
    padding: 0.75rem;
    border-radius: 6px;
    font-size: 0.9rem;
    font-weight: 500;
}

.status-message.success {
    background-color: rgba(16, 185, 129, 0.1);
    color: #059669;
}

.status-message.error {
    background-color: rgba(239, 68, 68, 0.1);
    color: #dc2626;
}
```

### File: frontend\pages\MyJobs.jsx
```jsx
import { useState, useEffect, useRef } from 'react'
import API from '../src/api'
import { useAuth } from '../context/AuthContext'
import JobCard from '../components/JobCard'
import './MyJobs.css'

export default function MyJobs() {
    const { user, updateUser } = useAuth()
    const [file, setFile] = useState(null)
    const [uploading, setUploading] = useState(false)
    const [message, setMessage] = useState('')
    const [error, setError] = useState('')
    const [skills, setSkills] = useState('')
    const [jobs, setJobs] = useState([])
    const [suggestedJobs, setSuggestedJobs] = useState([])
    const [appliedJobIds, setAppliedJobIds] = useState(new Set())
    const [isEditing, setIsEditing] = useState(false)
    const fileInputRef = useRef(null)

    // Fetch jobs and user apps to calculate status
    useEffect(() => {
        const fetchData = async () => {
            try {
                const jobsRes = await API.get('/api/jobs', {
                    headers: { Authorization: `Bearer ${user.token}` }
                })
                setJobs(jobsRes.data)

                const appsRes = await API.get('/api/applications/my-work', {
                    headers: { Authorization: `Bearer ${user.token}` }
                })
                const ids = new Set(appsRes.data.map(app => app.jobId._id || app.jobId))
                setAppliedJobIds(ids)
            } catch (error) {
                console.error("Error fetching data:", error)
            }
        }
        if (user) fetchData()
    }, [user])

    // Filter jobs based on skills
    useEffect(() => {
        if (!skills.trim()) {
            setSuggestedJobs([])
            return
        }
        const skillList = skills.toLowerCase().split(',').map(s => s.trim())
        const filtered = jobs.filter(job => {
            const titleMatch = skillList.some(skill => job.title.toLowerCase().includes(skill))
            const descMatch = skillList.some(skill => job.description.toLowerCase().includes(skill))
            return titleMatch || descMatch
        })
        setSuggestedJobs(filtered)
    }, [skills, jobs])

    const handleFileChange = (e) => {
        setFile(e.target.files[0])
        setMessage('')
        setError('')
    }

    const handleUpload = async (e) => {
        e.preventDefault()
        if (!file) {
            setError('Please select a PDF file first.')
            return
        }

        console.log("Selected file:", file)

        const formData = new FormData()
        formData.append('resume', file)

        // Log FormData entries for debugging
        for (let pair of formData.entries()) {
            console.log(pair[0] + ', ' + pair[1]);
        }

        setUploading(true)
        setError('')
        setMessage('')

        try {
            // Do NOT manually set Content-Type for FormData; let the browser set it with the boundary
            const { data } = await API.post('/api/upload', formData, {
                headers: {
                    Authorization: `Bearer ${user.token}`
                }
            })

            // Backend returns { success: true, filePath: '...', fileName: '...' }
            if (data.success || data.filePath) {
                updateUser({ resumeUrl: data.filePath })
                setMessage(`Success! Uploaded: ${data.fileName || file.name}`)
                setFile(null)
                setIsEditing(false) // Hide form on success
                // Reset file input
                if (fileInputRef.current) {
                    fileInputRef.current.value = ''
                }
            }
        } catch (error) {
            console.error("Upload error:", error)
            setError(error.response?.data?.message || 'Upload failed. Please try again.')
        } finally {
            setUploading(false)
        }
    }

    const handleApply = async (jobId) => {
        try {
            await API.post(`/api/applications/${jobId}`, {}, {
                headers: { Authorization: `Bearer ${user.token}` }
            })
            setAppliedJobIds(prev => new Set(prev).add(jobId))
        } catch (error) {
            alert(error.response?.data?.message || "Failed to apply")
        }
    }

    const handleDeleteResume = async () => {
        if (!window.confirm("Are you sure you want to remove your resume?")) return;
        setUploading(true);
        try {
            await API.delete('/api/upload', {
                headers: { Authorization: `Bearer ${user.token}` }
            })
            updateUser({ resumeUrl: null })
            setMessage('Resume removed successfully.')
            setIsEditing(true) // Switch back to upload mode
        } catch (error) {
            console.error("Delete error:", error)
            setError('Failed to delete resume.')
        } finally {
            setUploading(false)
        }
    }

    return (
        <main className="page my-jobs">
            <div className="container">
                <header className="my-jobs__header">
                    <h1 className="my-jobs__title">Manage Resume & Suggestions</h1>
                </header>

                <div className="my-jobs__grid">
                    {/* Resume Upload Card */}
                    <section className="job-card-section">
                        <div className="job-card__header">
                            <h2 className="job-card__title">
                                <span className="job-card__icon">📄</span> Resume Upload
                            </h2>
                            <p className="job-card__subtext">Upload your resume (PDF only) to allow one-click applications.</p>
                        </div>

                        {!isEditing && user.resumeUrl ? (
                            <div className="resume-view-mode">
                                <div className="status-message success" style={{ marginBottom: '1rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                    <span>✅ Resume on file. <a href={user.resumeUrl} target="_blank" rel="noopener noreferrer" style={{ textDecoration: 'underline' }}>View Current Resume</a></span>

                                    <button
                                        onClick={handleDeleteResume}
                                        title="Remove Resume"
                                        style={{
                                            background: 'none',
                                            border: 'none',
                                            cursor: 'pointer',
                                            fontSize: '1.2rem',
                                            color: '#ef4444',
                                            padding: '4px 8px',
                                            borderRadius: '4px',
                                            marginLeft: '10px'
                                        }}
                                        className="btn-delete-resume"
                                    >
                                        ✕
                                    </button>
                                </div>
                                <button className="btn-find" style={{ width: '100%' }} onClick={() => setIsEditing(true)}>
                                    Update Resume
                                </button>
                            </div>
                        ) : (
                            <form onSubmit={handleUpload} className="resume-upload-form">
                                <input
                                    ref={fileInputRef}
                                    type="file"
                                    onChange={handleFileChange}
                                    accept=".pdf"
                                    className="file-input"
                                />
                                <div style={{ display: 'flex', gap: '0.5rem' }}>
                                    <button type="submit" className="btn-upload" disabled={uploading}>
                                        {uploading ? 'Uploading...' : 'Upload Resume'}
                                    </button>
                                    {user.resumeUrl && <button type="button" className="btn-upload" style={{ background: '#6b7280' }} onClick={() => setIsEditing(false)}>Cancel</button>}
                                </div>
                            </form>
                        )}

                        {message && (
                            <p className="status-message success">
                                {message}
                            </p>
                        )}
                        {error && (
                            <p className="status-message error">
                                {error}
                            </p>
                        )}
                    </section>

                    {/* Job Suggestions Card */}
                    <section className="job-card-section">
                        <div className="job-card__header">
                            <h2 className="job-card__title">
                                <span className="job-card__icon">💡</span> Job Suggestions
                            </h2>
                            <p className="job-card__subtext">Enter your skills to see matching opportunities immediately.</p>
                        </div>

                        <div className="skills-input-group">
                            <input
                                type="text"
                                className="modern-input"
                                placeholder="e.g. React, Node, Java, Design"
                                value={skills}
                                onChange={(e) => setSkills(e.target.value)}
                            />
                            <button className="btn-find" onClick={() => { }}>
                                Find Jobs
                            </button>
                        </div>
                        <p className="helper-text">Start typing skills (comma separated) to see suggestions below.</p>
                    </section>

                    {/* Results Area */}
                    <div className="suggested-jobs">
                        {skills && suggestedJobs.length > 0 && (
                            <p className="status-message" style={{ color: 'var(--text-secondary)', marginBottom: '1rem' }}>
                                Found {suggestedJobs.length} matching job{suggestedJobs.length !== 1 && 's'}:
                            </p>
                        )}
                        {suggestedJobs.length > 0 ? (
                            <div className="jobs__list">
                                {suggestedJobs.map(job => (
                                    <JobCard
                                        key={job._id}
                                        job={job}
                                        isApplied={appliedJobIds.has(job._id)}
                                        onApply={handleApply}
                                    />
                                ))}
                            </div>
                        ) : (
                            skills && (
                                <div className="status-message error" style={{ background: 'var(--bg-primary)', border: '1px solid var(--border-color)', color: 'var(--text-secondary)' }}>
                                    <p>No matching jobs found for "{skills}".</p>
                                    <p style={{ fontSize: '0.8rem', marginTop: '0.25rem' }}>Try broader terms like "Developer", "Engineer", or "Manager".</p>
                                    {jobs.length === 0 && <p style={{ fontSize: '0.8rem', color: 'red', marginTop: '0.5rem' }}>Debug: No jobs loaded from database.</p>}
                                </div>
                            )
                        )}
                    </div>
                </div>
            </div>
        </main>
    )
}

```

### File: frontend\pages\MyWork.css
```css
/* MyWork.css - Enhancing the Application Status Table */

.dashboard__table-container {
    overflow-x: auto;
    background: var(--bg-secondary);
    border-radius: 12px;
    border: 1px solid var(--border-color);
    box-shadow: var(--shadow-sm);
}

.dashboard__table {
    width: 100%;
    border-collapse: collapse;
    min-width: 600px;
    /* Ensure scroll on small screens */
}

.dashboard__th {
    text-align: left;
    padding: 1rem 1.5rem;
    background: var(--bg-tertiary);
    color: var(--text-secondary);
    font-size: 0.85rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    border-bottom: 1px solid var(--border-color);
}

.dashboard__td {
    padding: 1.25rem 1.5rem;
    color: var(--text-primary);
    font-size: 0.95rem;
    border-bottom: 1px solid var(--border-color);
    vertical-align: middle;
}

.dashboard__tr:last-child .dashboard__td {
    border-bottom: none;
}

.dashboard__tr:hover {
    background-color: var(--bg-tertiary);
    transition: background-color 0.2s ease;
}

/* Status Badges */
.dashboard__status-badge {
    display: inline-flex;
    align-items: center;
    padding: 0.35rem 0.75rem;
    border-radius: 9999px;
    font-size: 0.85rem;
    font-weight: 500;
    text-transform: capitalize;
}

.status-applied {
    background: rgba(59, 130, 246, 0.1);
    color: #3b82f6;
    border: 1px solid rgba(59, 130, 246, 0.2);
}

.status-interview {
    background: rgba(249, 115, 22, 0.1);
    color: #f97316;
    border: 1px solid rgba(249, 115, 22, 0.2);
}

.status-accepted {
    background: rgba(16, 185, 129, 0.1);
    color: #10b981;
    border: 1px solid rgba(16, 185, 129, 0.2);
}

.status-rejected {
    background: rgba(239, 68, 68, 0.1);
    color: #ef4444;
    border: 1px solid rgba(239, 68, 68, 0.2);
}

/* Empty State */
.dashboard__empty {
    text-align: center;
    padding: 3rem 1rem;
    background: var(--bg-secondary);
    border-radius: 12px;
    border: 1px solid var(--border-color);
}

.dashboard__empty-title {
    font-size: 1.25rem;
    font-weight: 600;
    margin-bottom: 0.5rem;
    color: var(--text-primary);
}

.dashboard__empty p {
    color: var(--text-secondary);
    margin-bottom: 1.5rem;
}

.dashboard__empty-btn {
    display: inline-block;
    padding: 0.75rem 1.5rem;
    background: var(--color-primary);
    color: white;
    font-weight: 600;
    border-radius: 8px;
    text-decoration: none;
    transition: background 0.2s;
}

.dashboard__empty-btn:hover {
    background: var(--color-primary-dark, #0d9488);
}
```

### File: frontend\pages\MyWork.jsx
```jsx
import { useState, useEffect } from 'react'
import API from '../src/api'
import { useAuth } from '../context/AuthContext'
import './Dashboard.css'
import './MyWork.css'

export default function MyWork() {
    const [applications, setApplications] = useState([])
    const { user } = useAuth()
    const [loading, setLoading] = useState(true)

    useEffect(() => {
        const fetchApplications = async () => {
            try {
                const { data } = await API.get('/api/applications/my-work', {
                    headers: { Authorization: `Bearer ${user.token}` }
                })
                setApplications(data)
            } catch (error) {
                console.error("Error fetching applications:", error)
            } finally {
                setLoading(false)
            }
        }

        if (user) fetchApplications()
    }, [user])

    if (loading) return <div className="container">Loading...</div>

    const totalApplications = applications.length
    const interviewsScheduled = applications.filter(app => app.status === 'interview').length

    const getStatusColor = (status) => {
        switch (status) {
            case 'accepted': return 'green'
            case 'rejected': return 'red'
            case 'interview': return 'orange'
            default: return 'blue'
        }
    }

    return (
        <main className="dashboard">
            <div className="container">
                <header style={{ marginBottom: '2rem' }}>
                    <h1 className="dashboard__title">Career</h1>
                    <p className="dashboard__subtitle">Welcome back, {user?.name}</p>
                </header>

                {/* Profile Snapshot - keeping it compact */}
                <div className="user-details-card" style={{
                    background: 'var(--bg-secondary)',
                    padding: '1.5rem',
                    borderRadius: '12px',
                    marginBottom: '2rem',
                    boxShadow: 'var(--shadow-sm)',
                    border: '1px solid var(--border-color)',
                    display: 'flex',
                    flexWrap: 'wrap',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    gap: '1rem'
                }}>
                    <div style={{ display: 'grid', gap: '0.25rem' }}>
                        <h2 style={{ fontSize: '1.25rem', fontWeight: '600', color: 'var(--text-primary)' }}>{user?.role} Profile</h2>
                        <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>{user?.email}</p>
                    </div>
                    <div>
                        <a href="/my-jobs" style={{
                            color: 'rgb(16, 185, 129)',
                            textDecoration: 'none',
                            fontWeight: '600',
                            fontSize: '0.95rem',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '0.5rem'
                        }}>
                            Manage Resume & Matches →
                        </a>
                    </div>
                </div>

                {/* Professional Stats */}
                <div className="dashboard__stats">
                    <div className="dashboard__stat-card">
                        <span className="dashboard__stat-label">Total Applications</span>
                        <span className="dashboard__stat-value">{totalApplications}</span>
                    </div>
                    <div className="dashboard__stat-card">
                        <span className="dashboard__stat-label">Interviews Scheduled</span>
                        <span className="dashboard__stat-value">{interviewsScheduled}</span>
                        {interviewsScheduled > 0 && (
                            <span className="stat-detail">
                                {applications.some(app => {
                                    if (app.status !== 'interview' || !app.interviewDate) return false;
                                    const today = new Date().toISOString().split('T')[0];
                                    return app.interviewDate === today;
                                })
                                    ? "Next: Today"
                                    : "No interviews today"}
                            </span>
                        )}
                    </div>
                </div>

                {/* Applications Table / Empty State */}
                <div className="applications-section" style={{ marginTop: '2.5rem' }}>
                    <h2 className="dashboard__section-title">Application Status</h2>

                    {applications.length === 0 ? (
                        <div className="dashboard__empty">
                            <h3 className="dashboard__empty-title">No applications yet</h3>
                            <p>Start applying to jobs to track your progress here.</p>
                            <a href="/jobs" className="dashboard__empty-btn">Browse Jobs</a>
                        </div>
                    ) : (
                        <div className="dashboard__table-container">
                            <table className="dashboard__table">
                                <thead>
                                    <tr>
                                        <th className="dashboard__th">Role</th>
                                        <th className="dashboard__th">Company</th>
                                        <th className="dashboard__th">Status</th>
                                        <th className="dashboard__th">Applied On</th>
                                        <th className="dashboard__th">Details</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {applications.map(app => (
                                        <tr key={app._id} className="dashboard__tr">
                                            <td className="dashboard__td" style={{ fontWeight: '500' }}>{app.jobId.title}</td>
                                            <td className="dashboard__td">{app.jobId.company}</td>
                                            <td className="dashboard__td">
                                                <span className={`dashboard__status-badge status-${app.status}`}>
                                                    {app.status === 'accepted' ? 'Selected' : app.status}
                                                </span>
                                            </td>
                                            <td className="dashboard__td">{new Date(app.appliedAt).toLocaleDateString()}</td>
                                            <td className="dashboard__td">
                                                {app.status === 'interview' ? (
                                                    <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                                                        {app.interviewDate} @ {app.interviewTime}
                                                    </span>
                                                ) : '—'}
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                </div>
            </div>
        </main>
    )
}

```

### File: frontend\pages\Preferences.css
```css
.preferences__card {
  padding: 1.5rem;
  background: var(--color-surface);
  border-radius: var(--radius);
  box-shadow: var(--shadow-sm);
  border: 1px solid var(--color-border);
  margin-bottom: 1.5rem;
}

.preferences__section-title {
  font-size: 1rem;
  font-weight: 600;
  color: var(--color-text);
  margin-bottom: 1rem;
}

.preferences__row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  flex-wrap: wrap;
}

.preferences__label {
  font-size: 0.9375rem;
  color: var(--color-text-muted);
}

.preferences__toggle {
  width: 48px;
  height: 26px;
  padding: 2px;
  background: var(--color-border);
  border: none;
  border-radius: var(--radius-pill);
  cursor: pointer;
  transition: background 0.2s ease;
}

.preferences__toggle:hover {
  background: var(--color-text-muted);
}

.preferences__toggle--on {
  background: var(--color-primary);
}

.preferences__toggle-slider {
  display: block;
  width: 22px;
  height: 22px;
  background: var(--color-surface);
  border-radius: 50%;
  box-shadow: var(--shadow-sm);
  transition: transform 0.2s ease;
}

.preferences__toggle--on .preferences__toggle-slider {
  transform: translateX(22px);
}

.preferences__theme-btns {
  display: flex;
  gap: 0.5rem;
}

.preferences__theme-btn {
  padding: 0.5rem 1rem;
  font-size: 0.875rem;
  font-weight: 500;
  color: var(--color-text-muted);
  background: var(--color-bg-section);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-sm);
  transition: background 0.2s ease, border-color 0.2s ease, color 0.2s ease;
}

.preferences__theme-btn:hover {
  border-color: var(--color-secondary);
  color: var(--color-secondary);
}

.preferences__theme-btn--active {
  background: var(--color-primary);
  border-color: var(--color-primary);
  color: var(--color-secondary);
}

```

### File: frontend\pages\Preferences.jsx
```jsx
import { useState } from 'react'
import './Preferences.css'

export default function Preferences() {
  const [notifications, setNotifications] = useState(true)
  const [theme, setTheme] = useState('light')

  return (
    <main className="page preferences">
      <div className="container">
        <h1 className="page__title">Preferences</h1>
        <p className="page__subtitle">Customize your experience</p>
        <div className="preferences__card">
          <h2 className="preferences__section-title">Notifications</h2>
          <div className="preferences__row">
            <span className="preferences__label">Email notifications</span>
            <button
              type="button"
              className={`preferences__toggle ${notifications ? 'preferences__toggle--on' : ''}`}
              onClick={() => setNotifications((p) => !p)}
              aria-label="Toggle notifications"
            >
              <span className="preferences__toggle-slider" />
            </button>
          </div>
        </div>
        <div className="preferences__card">
          <h2 className="preferences__section-title">Theme</h2>
          <div className="preferences__row">
            <span className="preferences__label">App theme (UI only)</span>
            <div className="preferences__theme-btns">
              <button
                type="button"
                className={`preferences__theme-btn ${theme === 'light' ? 'preferences__theme-btn--active' : ''}`}
                onClick={() => setTheme('light')}
              >
                Light
              </button>
              <button
                type="button"
                className={`preferences__theme-btn ${theme === 'dark' ? 'preferences__theme-btn--active' : ''}`}
                onClick={() => setTheme('dark')}
              >
                Dark
              </button>
            </div>
          </div>
        </div>
      </div>
    </main>
  )
}

```

### File: frontend\pages\Register.jsx
```jsx
import { useState, useEffect } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import './Auth.css'

export default function Register() {
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [role, setRole] = useState('user')
  const { register, user } = useAuth()
  const navigate = useNavigate()
  const [error, setError] = useState('')

  useEffect(() => {
    if (user) {
      if (user.role === 'admin') {
        navigate('/admin')
      } else {
        navigate('/jobs')
      }
    }
  }, [user, navigate])

  const handleSubmit = async (e) => {
    e.preventDefault()
    const result = await register(name, email, password, role)
    if (!result.success) {
      setError(result.message)
    }
  }

  return (
    <main className="auth">
      <div className="auth__container container">
        <div className="auth__card">
          <h1 className="auth__title">Register</h1>
          <p className="auth__subtitle">Create your account</p>
          {error && <p className="error-message">{error}</p>}
          <form className="auth__form" onSubmit={handleSubmit}>
            <div className="auth__field">
              <label htmlFor="register-name" className="auth__label">
                Name
              </label>
              <input
                id="register-name"
                type="text"
                placeholder="Your name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="auth__input"
                required
              />
            </div>
            <div className="auth__field">
              <label htmlFor="register-email" className="auth__label">
                Email
              </label>
              <input
                id="register-email"
                type="email"
                placeholder="you@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="auth__input"
                required
              />
            </div>
            <div className="auth__field">
              <label htmlFor="register-password" className="auth__label">
                Password
              </label>
              <div className="auth__password-wrapper">
                <input
                  id="register-password"
                  type={showPassword ? "text" : "password"}
                  placeholder=""
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="auth__input"
                  required
                />
                <button
                  type="button"
                  className="auth__password-toggle"
                  onClick={() => setShowPassword(!showPassword)}
                  aria-label={showPassword ? "Hide password" : "Show password"}
                >
                  {showPassword ? (
                    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
                      <line x1="1" y1="1" x2="23" y2="23"></line>
                    </svg>
                  ) : (
                    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                      <circle cx="12" cy="12" r="3"></circle>
                    </svg>
                  )}
                </button>
              </div>
            </div>
            <button type="submit" className="auth__btn">
              Register
            </button>
          </form>
          <p className="auth__footer">
            Already have an account?{' '}
            <Link to="/login" className="auth__link">
              Login
            </Link>
          </p>
        </div>
      </div>
    </main>
  )
}

```

### File: frontend\src\api.js
```js
import axios from 'axios';

const API = axios.create({
    baseURL: import.meta.env.VITE_API_URL || 'http://localhost:5000',
});

// Add a request interceptor to attach the token if it exists (optional but good practice)
API.interceptors.request.use((req) => {
    // If you store token in localStorage, you can attach it here
    // const user = JSON.parse(localStorage.getItem('user'));
    // if (user?.token) {
    //     req.headers.Authorization = `Bearer ${user.token}`;
    // }
    return req;
});

export default API;

```

### File: frontend\vite.config.js
```js
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  base: '/CareerSetu.in/',
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:5000',
        changeOrigin: true,
        secure: false,
      },
      '/uploads': {
        target: 'http://localhost:5000',
        changeOrigin: true,
        secure: false,
      }
    },
  },
})

```

### File: README.md
```md
# CareerSetu.in

CareerSetu.in is a modern full-stack job portal web application built using the MERN stack. It enables job seekers to discover and track job applications while allowing administrators to manage job postings, applicants, and hiring workflows through role-based dashboards.

The platform supports secure authentication, resume uploads, application tracking, and real-world recruitment workflows, making it suitable for both learning and portfolio showcasing.

## 🌐 Live Demo

Hosted on:
🔗 **Coming Soon** (Vercel / Render)

## ⭐ Like the Project?

If you find this project useful or interesting, consider starring 🌟 the repository to show your support.
It motivates me to keep improving the project and adding more features.
👉 [Give it a Star on GitHub](https://github.com/ombiswal-04/job-tracker)

## 📦 Tech Stack

### Frontend
- **React** (Vite)
- **React Router DOM**
- **Context API** (Auth & Theme)
- **CSS**

### Backend
- **Node.js**
- **Express.js**
- **MongoDB** with **Mongoose**

### Authentication
- **JWT-based Authentication**

### File Upload
- **Multer** (Resume Uploads)

### Hosting
- **Frontend**: Vercel / Netlify
- **Backend**: Render / Railway / Heroku

## 🚀 Features

### 🧾 User Authentication
- Signup and login
- JWT-based secure authentication
- Role-based access (User / Admin)

### 👤 Job Seekers
- Browse and filter job listings
- Apply to jobs (internal or external links)
- Track application status (Applied, Interview, Accepted, Rejected)
- Upload and manage resumes
- Manage profile and preferences

### 🛠️ Admin
- Admin dashboard overview
- Create, update, and delete job postings
- View and manage applicants
- Schedule interviews
- Control hiring workflows

## ⚙️ Getting Started Locally

### 1. Clone the Repository
```bash
git clone https://github.com/ombiswal-04/job-tracker.git
cd job-tracker
```

### 2. Install Dependencies

**Backend**
```bash
cd backend
npm install
```

**Frontend**
```bash
cd ../frontend
npm install
```

### 3. Create Environment Files

✅ **Backend .env** (inside `/backend`)
```env
PORT=5000
MONGO_URI=your_mongodb_connection_string
JWT_SECRET=your_jwt_secret
```

✅ **(Optional) Frontend .env** (inside `/frontend`)
```env
VITE_API_URL=http://localhost:5000
```
➡️ ***Make sure your MongoDB database is running (local or Atlas).***

### 4. Start the App

**Run Backend**
```bash
cd backend
npm start
```

**Run Frontend**
```bash
cd ../frontend
npm run dev
```

The app will run on:
- **Frontend**: `http://localhost:5173`
- **Backend**: `http://localhost:5000`

## 🌐 Deployment Notes

### ⚙️ CORS Settings (Backend – Production)
```javascript
app.use(cors({
  origin: "https://your-frontend-url",
  credentials: true
}));
```

### 🔐 JWT Usage
- Tokens are generated on login
- Protected routes for users and admins
- Role-based authorization enforced on backend

## 📁 Project Structure

```
CareerSetu/
├── backend/
│   ├── config/
│   ├── controllers/
│   ├── middleware/
│   ├── models/
│   ├── routes/
│   ├── uploads/
│   └── server.js
│
├── frontend/
│   ├── components/
│   ├── pages/
│   ├── context/
│   └── App.jsx
│
├── README.md
```

## 👥 Author

Built by **Om Biswal** 💻
Open to contributions, suggestions, and collaboration.

## 📝 License

This project is licensed under the **ISC License**.
You are free to use, modify, and distribute this software under the terms of the license.

```

