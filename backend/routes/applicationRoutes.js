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
