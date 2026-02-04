import { useState, useEffect } from 'react'
import API from '../src/api'
import JobCard from '../components/JobCard'
import { useAuth } from '../context/AuthContext'
import './Jobs.css'

export default function Jobs() {
  const [jobs, setJobs] = useState([])
  const [appliedJobIds, setAppliedJobIds] = useState(new Set())
  const { user } = useAuth()
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const fetchData = async () => {
      try {
        const jobsRes = await API.get('/api/jobs', {
          headers: user ? { Authorization: `Bearer ${user.token}` } : {}
        })
        setJobs(jobsRes.data)

        if (user) {
          const appsRes = await API.get('/api/applications/my-work', {
            headers: { Authorization: `Bearer ${user.token}` }
          })
          const ids = new Set(appsRes.data.map(app => app.jobId._id || app.jobId))
          setAppliedJobIds(ids)
        }
      } catch (error) {
        console.error("Error fetching data:", error)
      } finally {
        setLoading(false)
      }
    }

    fetchData()
  }, [user])

  const handleApply = async (jobId) => {
    if (!user) {
      alert('Please login to apply')
      return
    }

    if (!user.resumeUrl) {
      alert('You must upload a resume before applying. Please go to "Career" section to upload your resume.')
      return
    }
    try {
      await API.post(`/api/applications/${jobId}`, {}, {
        headers: { Authorization: `Bearer ${user.token}` }
      })
      setAppliedJobIds(prev => new Set(prev).add(jobId))
    } catch (error) {
      console.error("Error applying:", error)
      alert(error.response?.data?.message || "Failed to apply")
    }
  }

  if (loading) return <div className="container">Loading jobs...</div>

  return (
    <main className="page jobs">
      <div className="container">
        <h1 className="page__title">Jobs in India</h1>
        <p className="page__subtitle">Find your dream job today</p>
        <div className="jobs__list">
          {jobs.map((job) => (
            <JobCard
              key={job._id}
              job={job}
              isApplied={appliedJobIds.has(job._id)}
              onApply={handleApply}
            />
          ))}
          {jobs.length === 0 && <p>No jobs found.</p>}
        </div>
      </div>
    </main>
  )
}
