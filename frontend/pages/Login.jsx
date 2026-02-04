import { useState, useEffect } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import './Auth.css'

export default function Login() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const { login, user } = useAuth()
  const navigate = useNavigate()
  const [error, setError] = useState('')

  useEffect(() => {
    if (user) {
      if (user.role === 'admin') {
        navigate('/admin')
      } else {
        navigate('/jobs')
      }
    }
  }, [user, navigate])

  const handleSubmit = async (e) => {
    e.preventDefault()
    const result = await login(email, password)
    if (!result.success) {
      setError(result.message)
    }
  }

  return (
    <main className="auth">
      <div className="auth__container container">
        <div className="auth__card">
          <h1 className="auth__title">Login</h1>
          <p className="auth__subtitle">Sign in to your account</p>
          {error && <p className="error-message">{error}</p>}
          <form className="auth__form" onSubmit={handleSubmit}>
            <div className="auth__field">
              <label htmlFor="login-email" className="auth__label">
                Email
              </label>
              <input
                id="login-email"
                type="email"
                placeholder="you@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="auth__input"
                required
              />
            </div>
            <div className="auth__field">
              <label htmlFor="login-password" className="auth__label">
                Password
              </label>
              <div className="auth__password-wrapper">
                <input
                  id="login-password"
                  type={showPassword ? "text" : "password"}
                  placeholder=""
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="auth__input"
                  required
                />
                <button
                  type="button"
                  className="auth__password-toggle"
                  onClick={() => setShowPassword(!showPassword)}
                  aria-label={showPassword ? "Hide password" : "Show password"}
                >
                  {showPassword ? (
                    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
                      <line x1="1" y1="1" x2="23" y2="23"></line>
                    </svg>
                  ) : (
                    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                      <circle cx="12" cy="12" r="3"></circle>
                    </svg>
                  )}
                </button>
              </div>
            </div>
            <button type="submit" className="auth__btn">
              Login
            </button>
          </form>
          <p className="auth__footer">
            Don&apos;t have an account?{' '}
            <Link to="/register" className="auth__link">
              Register
            </Link>
          </p>
        </div>
      </div>
    </main>
  )
}
