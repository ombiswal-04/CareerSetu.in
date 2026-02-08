'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import API from '@/lib/api';
import { useAuth } from '@/context/AuthContext';
import ProtectedRoute from '@/components/ProtectedRoute';
import '@/styles/Dashboard.css';
import '@/styles/MyWork.css';

function MyWorkContent() {
    const [applications, setApplications] = useState([]);
    const { user } = useAuth();
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchApplications = async () => {
            try {
                const { data } = await API.get('/api/applications/my-work', {
                    headers: { Authorization: `Bearer ${user.token}` }
                });
                setApplications(data);
            } catch (error) {
                console.error("Error fetching applications:", error);
            } finally {
                setLoading(false);
            }
        };

        if (user) fetchApplications();
    }, [user]);

    if (loading) return <div className="container">Loading...</div>;

    const totalApplications = applications.length;
    const interviewsScheduled = applications.filter(app => app.status === 'interview').length;

    return (
        <main className="dashboard">
            <div className="container">
                <header style={{ marginBottom: '2rem' }}>
                    <h1 className="dashboard__title">Career</h1>
                    <p className="dashboard__subtitle">Welcome back, {user?.name}</p>
                </header>

                {/* Profile Snapshot */}
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
                        <Link href="/my-jobs" style={{
                            color: 'rgb(16, 185, 129)',
                            textDecoration: 'none',
                            fontWeight: '600',
                            fontSize: '0.95rem',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '0.5rem'
                        }}>
                            Manage Resume & Matches →
                        </Link>
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
                            <Link href="/jobs" className="dashboard__empty-btn">Browse Jobs</Link>
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
    );
}

export default function MyWork() {
    return (
        <ProtectedRoute>
            <MyWorkContent />
        </ProtectedRoute>
    );
}
