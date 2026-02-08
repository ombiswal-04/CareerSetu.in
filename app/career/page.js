'use client';

import ProtectedRoute from '@/components/ProtectedRoute';
import '@/styles/CareerHelp.css';

const HELP_CARDS = [
    { id: 1, title: 'Resume tips for Indian IT jobs', description: 'Learn how to craft a resume that stands out for Indian recruiters and ATS.' },
    { id: 2, title: 'How to crack campus placements', description: 'Prepare for aptitude tests, technical rounds, and HR interviews.' },
    { id: 3, title: 'Fresher vs experienced resume tips', description: 'Tailor your resume whether you are a fresher or experienced professional.' },
    { id: 4, title: 'Interview prep: service & product companies', description: 'Ace interviews at both IT services firms and product-based companies.' },
    { id: 5, title: 'MNC vs Startup careers in India', description: 'Understand growth, culture, and trade-offs when choosing your path.' },
];

function CareerContent() {
    return (
        <main className="page career-help">
            <div className="container">
                <h1 className="page__title">Career Help</h1>
                <p className="page__subtitle">Resources to advance your career in India</p>
                <div className="career-help__grid">
                    {HELP_CARDS.map((card) => (
                        <article key={card.id} className="career-help__card">
                            <h2 className="career-help__card-title">{card.title}</h2>
                            <p className="career-help__card-desc">{card.description}</p>
                        </article>
                    ))}
                </div>
            </div>
        </main>
    );
}

export default function Career() {
    return (
        <ProtectedRoute>
            <CareerContent />
        </ProtectedRoute>
    );
}
