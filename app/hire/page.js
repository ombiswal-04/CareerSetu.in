'use client';

import { useState, useEffect } from 'react';
import API from '@/lib/api';
import { useAuth } from '@/context/AuthContext';
import ProtectedRoute from '@/components/ProtectedRoute';
import '@/styles/Dashboard.css';
import '@/styles/Hire.css';

function HireContent() {
    const [applications, setApplications] = useState([]);
    const { user } = useAuth();
    const [loading, setLoading] = useState(true);
    const [scheduleData, setScheduleData] = useState({ id: null, date: '', time: '' });

    const fetchApplications = async () => {
        try {
            const { data } = await API.get('/applications/admin/all', {
                headers: { Authorization: `Bearer ${user.token}` }
            });
            setApplications(data);
        } catch (error) {
            console.error("Error fetching applications:", error);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        if (user) fetchApplications();
    }, [user]);

    const handleStatusUpdate = async (id, status) => {
        try {
            await API.put(`/applications/admin/${id}/status`, { status }, {
                headers: { Authorization: `Bearer ${user.token}` }
            });
            fetchApplications();
        } catch (error) {
            console.error("Error updating status:", error);
        }
    };

    const handleScheduleSubmit = async (e) => {
        e.preventDefault();
        try {
            await API.put(`/applications/admin/${scheduleData.id}/schedule`, {
                interviewDate: scheduleData.date,
                interviewTime: scheduleData.time
            }, {
                headers: { Authorization: `Bearer ${user.token}` }
            });
            setScheduleData({ id: null, date: '', time: '' });
            fetchApplications();
        } catch (error) {
            console.error("Error scheduling:", error);
        }
    };

    if (loading) return <div className="container">Loading...</div>;

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
                                        <div className="candidate-name">{app.userId?.name || 'Unknown User'}</div>
                                        <div className="candidate-job">Applied for: <strong>{app.jobId?.title || 'Unknown Job'}</strong></div>
                                        <div className="candidate-meta">{app.userId?.email || 'No email'}</div>
                                        <div className="candidate-resume-status" style={{ marginTop: '0.75rem' }}>
                                            {app.userId?.resumeUrl ? (
                                                <a
                                                    href={app.userId?.resumeUrl}
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
    );
}

export default function Hire() {
    return (
        <ProtectedRoute adminOnly={true}>
            <HireContent />
        </ProtectedRoute>
    );
}
