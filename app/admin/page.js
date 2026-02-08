'use client';

import { useState, useEffect } from 'react';
import API from '@/lib/api';
import { useAuth } from '@/context/AuthContext';
import ProtectedRoute from '@/components/ProtectedRoute';
import '@/styles/Dashboard.css';
import '@/styles/MyWork.css';

function AdminDashboardContent() {
    const { user } = useAuth();

    const [jobData, setJobData] = useState({
        title: '', company: '', location: '', salary: '', jobType: 'Full-time', description: '', source: 'CareerSetu', applyUrl: ''
    });
    const [postedJobs, setPostedJobs] = useState([]);
    const [editJobId, setEditJobId] = useState(null);

    const fetchJobs = async () => {
        try {
            const { data } = await API.get('/api/jobs', {
                headers: { Authorization: `Bearer ${user.token}` }
            });
            setPostedJobs(data);
        } catch (error) {
            console.error("Error fetching jobs:", error);
        }
    };

    useEffect(() => {
        fetchJobs();
    }, []);

    const handleJobSubmit = async (e) => {
        e.preventDefault();
        try {
            if (editJobId) {
                await API.put(`/api/jobs/${editJobId}`, jobData, {
                    headers: { Authorization: `Bearer ${user.token}` }
                });
                alert('Job Updated Successfully!');
                setEditJobId(null);
            } else {
                await API.post('/api/jobs', jobData, {
                    headers: { Authorization: `Bearer ${user.token}` }
                });
                alert('Job Posted Successfully!');
            }
            setJobData({ title: '', company: '', location: '', salary: '', jobType: 'Full-time', description: '', source: 'CareerSetu', applyUrl: '' });
            fetchJobs();
        } catch (error) {
            console.error("Error saving job:", error);
            alert('Failed to save job');
        }
    };

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
        });
        setEditJobId(job._id);
        window.scrollTo({ top: 0, behavior: 'smooth' });
    };

    const handleCancelEdit = () => {
        setEditJobId(null);
        setJobData({ title: '', company: '', location: '', salary: '', jobType: 'Full-time', description: '', source: 'CareerSetu', applyUrl: '' });
    };

    const handleDeleteJob = async (jobId) => {
        if (window.confirm('Are you sure you want to delete this job?')) {
            try {
                await API.delete(`/api/jobs/${jobId}`, {
                    headers: { Authorization: `Bearer ${user.token}` }
                });
                alert('Job Deleted Successfully');
                fetchJobs();
            } catch (error) {
                console.error("Error deleting job:", error);
                alert('Failed to delete job');
            }
        }
    };

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
                        <p style={{ color: 'var(--text-secondary)' }}>You haven&apos;t posted any jobs yet.</p>
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
    );
}

export default function AdminDashboard() {
    return (
        <ProtectedRoute adminOnly={true}>
            <AdminDashboardContent />
        </ProtectedRoute>
    );
}
