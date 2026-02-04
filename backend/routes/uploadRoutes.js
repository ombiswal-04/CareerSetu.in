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
