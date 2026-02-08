'use client';

import { useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useTheme } from '@/context/ThemeContext';
import { useAuth } from '@/context/AuthContext';
import './Navbar.css';

export default function Navbar() {
    const [menuOpen, setMenuOpen] = useState(false);
    const { theme, toggleTheme } = useTheme();
    const { user, logout } = useAuth();
    const pathname = usePathname();

    const toggleMenu = () => setMenuOpen((prev) => !prev);
    const closeMenu = () => setMenuOpen(false);

    // Helper to determine if a link is active
    const isActive = (path) => pathname === path;

    return (
        <header className="navbar">
            <div className="navbar__container container">
                <Link href="/" className="navbar__logo" onClick={closeMenu}>
                    CareerSetu
                </Link>

                <button
                    type="button"
                    className="navbar__toggle"
                    aria-label="Toggle menu"
                    aria-expanded={menuOpen}
                    onClick={toggleMenu}
                >
                    <span className={menuOpen ? 'navbar__toggle-bar open' : 'navbar__toggle-bar'} />
                    <span className={menuOpen ? 'navbar__toggle-bar open' : 'navbar__toggle-bar'} />
                    <span className={menuOpen ? 'navbar__toggle-bar open' : 'navbar__toggle-bar'} />
                </button>

                <nav className={`navbar__nav ${menuOpen ? 'navbar__nav--open' : ''}`}>
                    {(!user || user.role !== 'admin') && (
                        <>
                            <Link
                                href="/jobs"
                                className={`navbar__link ${isActive('/jobs') ? 'active' : ''}`}
                                onClick={closeMenu}
                            >
                                Jobs
                            </Link>
                            <Link
                                href="/talents"
                                className={`navbar__link ${isActive('/talents') ? 'active' : ''}`}
                                onClick={closeMenu}
                            >
                                Top Mentors
                            </Link>
                        </>
                    )}
                    {user && user.role !== 'admin' && (
                        <Link
                            href="/my-work"
                            className={`navbar__link ${isActive('/my-work') ? 'active' : ''}`}
                            onClick={closeMenu}
                        >
                            Career
                        </Link>
                    )}
                    {user && user.role === 'admin' && (
                        <>
                            <Link
                                href="/hire"
                                className={`navbar__link ${isActive('/hire') ? 'active' : ''}`}
                                onClick={closeMenu}
                            >
                                Hire
                            </Link>
                            <Link
                                href="/admin"
                                className={`navbar__link ${isActive('/admin') ? 'active' : ''}`}
                                onClick={closeMenu}
                            >
                                Admin Dashboard
                            </Link>
                        </>
                    )}
                    {user ? (
                        <div className="navbar__user-menu">
                            <Link
                                href="/my-work"
                                className="navbar__user-name"
                                onClick={closeMenu}
                                style={{ textDecoration: 'none', cursor: 'pointer' }}
                            >
                                Hi, {user.name}
                            </Link>
                            <button onClick={logout} className="navbar__link navbar__link--outline">Logout</button>
                        </div>
                    ) : (
                        <>
                            <Link href="/login" className="navbar__link navbar__link--outline" onClick={closeMenu}>
                                Login
                            </Link>
                            <Link href="/register" className="navbar__link navbar__link--primary" onClick={closeMenu}>
                                Register Now
                            </Link>
                        </>
                    )}
                    <button
                        className="navbar__theme-toggle"
                        onClick={toggleTheme}
                        aria-label="Toggle theme"
                    >
                        {theme === 'dark' ? '☀️' : '🌙'}
                    </button>
                </nav>
            </div>
        </header>
    );
}
