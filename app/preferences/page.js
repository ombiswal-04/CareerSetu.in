'use client';

import { useState } from 'react';
import ProtectedRoute from '@/components/ProtectedRoute';
import '@/styles/Preferences.css';

function PreferencesContent() {
    const [notifications, setNotifications] = useState(true);
    const [theme, setTheme] = useState('light');

    return (
        <main className="page preferences">
            <div className="container">
                <h1 className="page__title">Preferences</h1>
                <p className="page__subtitle">Customize your experience</p>
                <div className="preferences__card">
                    <h2 className="preferences__section-title">Notifications</h2>
                    <div className="preferences__row">
                        <span className="preferences__label">Email notifications</span>
                        <button
                            type="button"
                            className={`preferences__toggle ${notifications ? 'preferences__toggle--on' : ''}`}
                            onClick={() => setNotifications((p) => !p)}
                            aria-label="Toggle notifications"
                        >
                            <span className="preferences__toggle-slider" />
                        </button>
                    </div>
                </div>
                <div className="preferences__card">
                    <h2 className="preferences__section-title">Theme</h2>
                    <div className="preferences__row">
                        <span className="preferences__label">App theme (UI only)</span>
                        <div className="preferences__theme-btns">
                            <button
                                type="button"
                                className={`preferences__theme-btn ${theme === 'light' ? 'preferences__theme-btn--active' : ''}`}
                                onClick={() => setTheme('light')}
                            >
                                Light
                            </button>
                            <button
                                type="button"
                                className={`preferences__theme-btn ${theme === 'dark' ? 'preferences__theme-btn--active' : ''}`}
                                onClick={() => setTheme('dark')}
                            >
                                Dark
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </main>
    );
}

export default function Preferences() {
    return (
        <ProtectedRoute>
            <PreferencesContent />
        </ProtectedRoute>
    );
}
