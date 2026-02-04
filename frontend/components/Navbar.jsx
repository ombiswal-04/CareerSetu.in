import { useState } from 'react'
import { Link, NavLink } from 'react-router-dom'
import { useTheme } from '../context/ThemeContext'
import { useAuth } from '../context/AuthContext'
import './Navbar.css'

export default function Navbar() {
  const [menuOpen, setMenuOpen] = useState(false)
  const { theme, toggleTheme } = useTheme()
  const { user, logout } = useAuth()

  const toggleMenu = () => setMenuOpen((prev) => !prev)
  const closeMenu = () => setMenuOpen(false)

  return (
    <header className="navbar">
      <div className="navbar__container container">
        <Link to="/" className="navbar__logo" onClick={closeMenu}>
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
              <NavLink to="/jobs" className="navbar__link" onClick={closeMenu}>
                Jobs
              </NavLink>
              <NavLink to="/talents" className="navbar__link" onClick={closeMenu}>
                Top Mentors
              </NavLink>
            </>
          )}
          {user && user.role !== 'admin' && (
            <NavLink to="/my-work" className="navbar__link" onClick={closeMenu}>
              Career
            </NavLink>
          )}
          {user && user.role === 'admin' && (
            <>
              <NavLink to="/hire" className="navbar__link" onClick={closeMenu}>
                Hire
              </NavLink>
              <NavLink to="/admin" className="navbar__link" onClick={closeMenu}>
                Admin Dashboard
              </NavLink>
            </>
          )}
          {user ? (
            <div className="navbar__user-menu">
              <Link to="/my-work" className="navbar__user-name" onClick={closeMenu} style={{ textDecoration: 'none', cursor: 'pointer' }}>
                Hi, {user.name}
              </Link>
              <button onClick={logout} className="navbar__link navbar__link--outline">Logout</button>
            </div>
          ) : (
            <>
              <Link to="/login" className="navbar__link navbar__link--outline" onClick={closeMenu}>
                Login
              </Link>
              <Link to="/register" className="navbar__link navbar__link--primary" onClick={closeMenu}>
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
  )
}
