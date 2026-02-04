import './JobCard.css'

export default function JobCard({ job, isApplied, onApply }) {
  const {
    title,
    company,
    location,
    jobType = 'Full-time', // Map jobType from backend to type if needed, or use jobType
    salary,
    source = 'Admin',
    applyUrl,
    logoPlaceholder = true,
  } = job

  // Normalize source display and check if internal
  const displaySource = source === 'Admin' ? 'CareerSetu' : source
  const isInternal = displaySource === 'CareerSetu'

  return (
    <article className="job-card">
      <div className="job-card__header">
        <div className="job-card__logo">
          {logoPlaceholder ? (
            <div className="job-card__logo-placeholder" aria-hidden>
              {company?.charAt(0) || '?'}
            </div>
          ) : null}
        </div>
        <div className="job-card__header-content">
          <h3 className="job-card__title" title={title}>{title}</h3>
          <p className="job-card__company" title={company}>{company}</p>
          <span className="job-card__source-badge">
            Source: {displaySource}
          </span>
        </div>
      </div>

      <div className="job-card__body">
        <div className="job-card__tags">
          <span className="job-card__tag">{jobType}</span>
          <span className="job-card__location">
            <span className="job-card__location-icon">📍</span>
            {location}
          </span>
        </div>
      </div>

      <div className="job-card__footer">
        <div className="job-card__salary-wrapper">
          {salary ? (
            <p className="job-card__salary">{salary}</p>
          ) : (
            <p className="job-card__salary job-card__salary--hidden">Best in Industry</p>
          )}
        </div>
        <button
          type="button"
          className={`job-card__apply-btn ${isApplied ? 'job-card__apply-btn--applied' : ''}`}
          onClick={() => {
            if (!isInternal) {
              if (applyUrl) window.open(applyUrl, '_blank')
            } else {
              onApply && onApply(job._id)
            }
          }}
          disabled={isApplied || (!isInternal && !applyUrl)}
        >
          {!isInternal ? `Apply on ${displaySource}` : (isApplied ? 'Applied' : 'Apply Now')}
        </button>
      </div>
    </article>
  )
}
