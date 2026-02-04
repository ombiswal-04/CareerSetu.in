const express = require('express');
const router = express.Router();
const { createJob, getJobs } = require('../controllers/jobController');
const { protect, admin } = require('../middleware/authMiddleware');

router.route('/').post(protect, admin, createJob).get(protect, getJobs);
router.route('/:id').delete(protect, admin, require('../controllers/jobController').deleteJob).put(protect, admin, require('../controllers/jobController').updateJob);

module.exports = router;
