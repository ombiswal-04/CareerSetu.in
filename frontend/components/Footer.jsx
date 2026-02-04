import { Link } from 'react-router-dom'
import './Footer.css'

export default function Footer() {
  const currentYear = new Date().getFullYear()

  return (
    <footer className="footer">
      <div className="container">
        <div className="footer__grid">
          {/* Column 1: Brand & Connect */}
          <div className="footer__col footer__brand-col">
            <Link to="/" className="footer__logo">
              CareerSetu
            </Link>
            <div className="footer__socials">
              <h3 className="footer__social-title">Connect with us</h3>
              <div className="footer__social-icons">
                <a href="#" className="footer__icon" aria-label="Facebook">📘</a>
                <a href="#" className="footer__icon" aria-label="Instagram">📷</a>
                <a href="#" className="footer__icon" aria-label="Twitter">✖️</a>
                <a href="#" className="footer__icon" aria-label="LinkedIn">💼</a>
              </div>
            </div>
          </div>

          {/* Column 2: Company Links */}
          <div className="footer__col">
            <ul className="footer__list">
              <li className="footer__item"><Link to="/about" className="footer__link">About us</Link></li>
              <li className="footer__item"><Link to="/careers" className="footer__link">Careers</Link></li>
              <li className="footer__item"><Link to="/employer" className="footer__link">Employer home</Link></li>
              <li className="footer__item"><Link to="/sitemap" className="footer__link">Sitemap</Link></li>
              <li className="footer__item"><Link to="/credits" className="footer__link">Credits</Link></li>
            </ul>
          </div>

          {/* Column 3: Help & Support */}
          <div className="footer__col">
            <ul className="footer__list">
              <li className="footer__item"><Link to="/help" className="footer__link">Help center</Link></li>
              <li className="footer__item"><a href="#" className="footer__link">Summons/Notices</a></li>
              <li className="footer__item"><a href="#" className="footer__link">Grievances</a></li>
              <li className="footer__item"><a href="#" className="footer__link">Report issue</a></li>
            </ul>
          </div>

          {/* Column 4: Legal & Safety */}
          <div className="footer__col">
            <ul className="footer__list">
              <li className="footer__item"><Link to="/privacy" className="footer__link">Privacy policy</Link></li>
              <li className="footer__item"><Link to="/terms" className="footer__link">Terms & conditions</Link></li>
              <li className="footer__item"><a href="#" className="footer__link">Fraud alert</a></li>
              <li className="footer__item"><a href="#" className="footer__link">Trust & safety</a></li>
            </ul>
          </div>
        </div>

        <div className="footer__bottom">
          <p className="footer__copyright">
            © {currentYear} CareerSetu. Proudly Built with love in Bhubaneswar ❤️
          </p>
        </div>
      </div>
    </footer>
  )
}
