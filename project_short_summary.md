# Project Short Summary

Generated on: 2026-02-04T18:51:11.302Z

## 1. Project Structure
```text
├── backend
│   ├── config
│   │   └── db.js
│   ├── controllers
│   │   ├── .gitkeep
│   │   ├── applicationController.js
│   │   ├── authController.js
│   │   └── jobController.js
│   ├── middleware
│   │   ├── .gitkeep
│   │   └── authMiddleware.js
│   ├── models
│   │   ├── .gitkeep
│   │   ├── Application.js
│   │   ├── Job.js
│   │   └── User.js
│   ├── routes
│   │   ├── .gitkeep
│   │   ├── applicationRoutes.js
│   │   ├── authRoutes.js
│   │   ├── jobRoutes.js
│   │   └── uploadRoutes.js
│   ├── uploads
│   ├── .env
│   ├── .gitignore
│   ├── checkUser.js
│   ├── makeAdmin.js
│   ├── package.json
│   ├── resetPassword.js
│   ├── seedExternal.js
│   ├── server.js
│   └── verifyDB.js
├── frontend
│   ├── components
│   │   ├── Footer.css
│   │   ├── Footer.jsx
│   │   ├── JobCard.css
│   │   ├── JobCard.jsx
│   │   ├── Navbar.css
│   │   ├── Navbar.jsx
│   │   ├── New.jsx
│   │   └── ProtectedRoute.jsx
│   ├── context
│   │   ├── AuthContext.jsx
│   │   └── ThemeContext.jsx
│   ├── pages
│   │   ├── AdminDashboard.jsx
│   │   ├── Auth.css
│   │   ├── BrowseTalent.css
│   │   ├── BrowseTalent.jsx
│   │   ├── CareerHelp.css
│   │   ├── CareerHelp.jsx
│   │   ├── Dashboard.css
│   │   ├── Hire.css
│   │   ├── Hire.jsx
│   │   ├── Home.css
│   │   ├── Home.jsx
│   │   ├── Jobs.css
│   │   ├── Jobs.jsx
│   │   ├── Login.jsx
│   │   ├── MyJobs.css
│   │   ├── MyJobs.jsx
│   │   ├── MyWork.css
│   │   ├── MyWork.jsx
│   │   ├── Preferences.css
│   │   ├── Preferences.jsx
│   │   └── Register.jsx
│   ├── src
│   │   └── api.js
│   ├── .env.example
│   ├── .gitignore
│   ├── App.jsx
│   ├── index.css
│   ├── index.html
│   ├── main.jsx
│   ├── package.json
│   └── vite.config.js
└── README.md
```

## 2. Key File Contents (Models, Routes, Config)

### File: backend\models\.gitkeep
```text

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

### File: backend\routes\.gitkeep
```text

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

### File: frontend\App.jsx
```jsx
import { BrowserRouter, Routes, Route, useLocation } from 'react-router-dom'
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
        <BrowserRouter>
          <AppLayout />
        </BrowserRouter>
      </AuthProvider>
    </ThemeProvider>
  )
}

```

### File: frontend\package.json
```json
{
  "name": "job-tracker-frontend",
  "private": true,
  "version": "0.0.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "axios": "^1.13.4",
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.20.0"
  },
  "devDependencies": {
    "@vitejs/plugin-react": "^4.2.0",
    "vite": "^5.0.0"
  }
}

```

### File: README.md
```md
# Job Tracker

A comprehensive MERN stack application for tracking job applications, managing job postings, and connecting talents with opportunities. This platform serves both job seekers and administrators with dedicated dashboards and functionalities.

## 🚀 Features

### For Users (Job Seekers)
- **Browse Jobs**: View available job listings with filtering options.
- **Job Application**: Apply to jobs directly or via external links.
- **My Work**: Track status of applied jobs.
- **Profile Management**: Update user profile and preferences.
- **Authentication**: Secure Login and Registration.

### For Admins
- **Admin Dashboard**: Overview of platform statistics.
- **Job Management**: Create, Edit, and Delete job postings.
- **Talent Management**: Browse and manage registered talents.
- **Hiring**: Manage hiring processes.

## 🛠️ Tech Stack

### Frontend
- **React** (Vite)
- **React Router** for navigation
- **Context API** for state management (Auth, Theme)
- **CSS** for styling

### Backend
- **Node.js** & **Express.js**
- **MongoDB** with **Mongoose**
- **JWT** for Authentication
- **Multer** for file uploads

## 📦 Installation & Setup

### Prerequisites
- [Node.js](https://nodejs.org/) installed
- [MongoDB](https://www.mongodb.com/) installed or a MongoDB Atlas connection string

### 1. Clone the Repository
```bash
git clone https://github.com/ombiswal-04/job-tracker.git
cd job-tracker
```

### 2. Backend Setup
Navigate to the backend directory and install dependencies:
```bash
cd backend
npm install
```

Create a `.env` file in the `backend` directory with the following variables:
```env
PORT=5000
MONGO_URI=your_mongodb_connection_string
JWT_SECRET=your_jwt_secret_key
```

Start the backend server:
```bash
npm start
```
The server will run on `http://localhost:5000`.

### 3. Frontend Setup
Open a new terminal, navigate to the frontend directory, and install dependencies:
```bash
cd frontend
npm install
```

Create a `.env` file in the `frontend` directory (if required for API URL configuration):
```env
VITE_API_URL=http://localhost:5000
```
*(Note: Check file `src/config/api.js` or similar if the base URL is hardcoded or Env variable driven)*

Start the frontend development server:
```bash
npm run dev
```
The application will run on `http://localhost:5173` (or the port shown in your terminal).

## 🚀 Deployment

- **Frontend**: Can be deployed on Vercel, Netlify, or similar platforms.
- **Backend**: Can be deployed on Render, Railway, or Heroku.

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!

## 📄 License

This project is licensed under the ISC License.

```
