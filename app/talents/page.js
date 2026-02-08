'use client';

import { useState } from 'react';
import ProtectedRoute from '@/components/ProtectedRoute';
import '@/styles/BrowseTalent.css';

const MENTORS = [
    {
        id: 1,
        name: 'Priya Sharma',
        role: 'Senior Full Stack Developer',
        experience: '6+ years experience',
        location: 'Bengaluru',
        skills: ['React', 'Node.js', 'AWS', 'System Design'],
        rate: '₹1,200',
        unit: 'session',
        outcome: 'Career guidance · Code reviews',
        topMentor: true,
    },
    {
        id: 2,
        name: 'Rahul Verma',
        role: 'Data Scientist',
        experience: '8+ years experience',
        location: 'Hyderabad',
        skills: ['Python', 'Machine Learning', 'SQL'],
        rate: '₹1,500',
        unit: 'session',
        outcome: 'Live projects · Interview prep',
        topMentor: true,
    },
    {
        id: 3,
        name: 'Ananya Reddy',
        role: 'DevOps Engineer',
        experience: '5+ years experience',
        location: 'Chennai',
        skills: ['Docker', 'Kubernetes', 'CI/CD'],
        rate: '₹1,000',
        unit: 'session',
        outcome: 'Cloud Architecture · Hands-on labs',
        topMentor: true,
    },
    {
        id: 4,
        name: 'Arjun Kapoor',
        role: 'Product Designer',
        experience: '7+ years experience',
        location: 'Mumbai',
        skills: ['Figma', 'UX Research', 'Prototyping'],
        rate: '₹1,800',
        unit: 'session',
        outcome: 'Portfolio review · Design thinking',
        topMentor: true,
    },
];

function TalentsContent() {
    const [search, setSearch] = useState('');

    const filteredMentors = MENTORS.filter((mentor) => {
        const term = search.toLowerCase();
        return (
            mentor.name.toLowerCase().includes(term) ||
            mentor.role.toLowerCase().includes(term) ||
            mentor.skills.some(skill => skill.toLowerCase().includes(term))
        );
    });

    return (
        <main className="page browse-talent">
            <div className="container">
                <h1 className="page__title">Top Mentors in India</h1>
                <p className="page__subtitle">Learn directly from experienced professionals in your chosen field</p>
                <p className="page__value-prop">
                    Book 1-on-1 mentorship sessions, career guidance, and hands-on learning from industry experts.
                </p>

                <div className="browse-talent__search">
                    <input
                        type="text"
                        placeholder="Search mentors by skill, role, or technology (e.g. React, Data Science)..."
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                        className="browse-talent__input"
                    />
                </div>

                <div className="browse-talent__filters">
                    <button type="button" className="browse-talent__filter">Mentorship Area</button>
                    <button type="button" className="browse-talent__filter">Skills Taught</button>
                    <button type="button" className="browse-talent__filter">Mentor Location</button>
                    <button type="button" className="browse-talent__filter">Session Availability</button>
                </div>

                <div className="browse-talent__grid">
                    {filteredMentors.length > 0 ? (
                        filteredMentors.map((mentor) => (
                            <article key={mentor.id} className="talent-card">
                                {mentor.topMentor && (
                                    <div className="talent-card__badge-wrapper">
                                        <span className="talent-card__badge">TOP MENTOR</span>
                                    </div>
                                )}

                                <div className="talent-card__header">
                                    <div className="talent-card__avatar">
                                        {mentor.name?.charAt(0) || '?'}
                                    </div>
                                    <div className="talent-card__info">
                                        <h2 className="talent-card__name">{mentor.name}</h2>
                                        <p className="talent-card__role">{mentor.role}</p>
                                        <p className="talent-card__experience">{mentor.experience}</p>
                                    </div>
                                </div>

                                <div className="talent-card__body">
                                    <p className="talent-card__label">Teaches:</p>
                                    <div className="talent-card__skills">
                                        {mentor.skills.map((skill) => (
                                            <span key={skill} className="talent-card__chip">{skill}</span>
                                        ))}
                                    </div>
                                    <div className="talent-card__outcome">
                                        <span className="talent-card__check">✓</span> {mentor.outcome}
                                    </div>
                                </div>

                                <div className="talent-card__footer">
                                    <div className="talent-card__price">
                                        <span className="talent-card__rate">{mentor.rate}</span>
                                        <span className="talent-card__unit">/ {mentor.unit}</span>
                                    </div>
                                    <button type="button" className="talent-card__cta">
                                        Book Mentorship
                                    </button>
                                </div>
                            </article>
                        ))
                    ) : (
                        <div className="browse-talent__no-results">
                            <p>No mentors found matching &quot;{search}&quot;</p>
                        </div>
                    )}
                </div>
            </div>
        </main>
    );
}

export default function Talents() {
    return (
        <ProtectedRoute>
            <TalentsContent />
        </ProtectedRoute>
    );
}
