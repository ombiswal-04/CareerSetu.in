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
