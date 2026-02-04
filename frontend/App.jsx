import { BrowserRouter, Routes, Route, useLocation } from 'react-router-dom'
import Navbar from './components/Navbar'
import Footer from './components/Footer'
import Home from './pages/Home'
import Jobs from './pages/Jobs'

import BrowseTalent from './pages/BrowseTalent'
import CareerHelp from './pages/CareerHelp'
import Preferences from './pages/Preferences'
import Login from './pages/Login'
import Register from './pages/Register'
import ProtectedRoute from './components/ProtectedRoute'
import MyWork from './pages/MyWork'
import AdminDashboard from './pages/AdminDashboard'
import MyJobs from './pages/MyJobs'
import Hire from './pages/Hire'

const AUTH_ROUTES = ['/login', '/register']

function AppLayout() {
  return (
    <div className="app-layout">
      <div className="app-main">
        <Navbar />
        <div className="app-content">
          <Routes>
            <Route path="/" element={<Home />} />
            {/* Protected Routes for User */}
            <Route element={<ProtectedRoute />}>
              <Route path="/jobs" element={<Jobs />} />
              <Route path="/talents" element={<BrowseTalent />} />
              <Route path="/my-work" element={<MyWork />} />
              <Route path="/my-jobs" element={<MyJobs />} />
              <Route path="/career" element={<CareerHelp />} />

              <Route path="/preferences" element={<Preferences />} />
            </Route>

            {/* Protected Routes for Admin */}
            <Route element={<ProtectedRoute adminOnly={true} />}>
              <Route path="/admin" element={<AdminDashboard />} />
              <Route path="/hire" element={<Hire />} />
            </Route>



            <Route path="/login" element={<Login />} />
            <Route path="/register" element={<Register />} />
          </Routes>
        </div>
        <Footer />
      </div>
    </div>
  )
}

import { ThemeProvider } from './context/ThemeContext'
import { AuthProvider } from './context/AuthContext'

export default function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <BrowserRouter>
          <AppLayout />
        </BrowserRouter>
      </AuthProvider>
    </ThemeProvider>
  )
}
