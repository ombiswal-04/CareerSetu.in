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
