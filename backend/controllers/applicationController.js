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
