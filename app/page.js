'use client';

import { useState } from 'react';
import JobCard from '@/components/JobCard';
import './Home.css';

const TRENDING_JOBS = [
  {
    id: 1,
    title: 'Frontend Developer (React)',
    company: 'Flipkart',
    location: 'Bengaluru',
    type: 'Hybrid',
    salary: '₹12–18 LPA',
  },
  {
    id: 2,
    title: 'UI/UX Designer',
    company: 'Zoho',
    location: 'Chennai',
    type: 'Full-time',
    salary: '₹6–10 LPA',
  },
  {
    id: 3,
    title: 'Full Stack Developer (MERN)',
    company: 'Razorpay',
    location: 'Bengaluru',
    type: 'Remote',
    salary: '₹15–22 LPA',
  },
  {
    id: 4,
    title: 'Data Analyst',
    company: 'Accenture India',
    location: 'Hyderabad',
    type: 'Full-time',
    salary: '₹8–12 LPA',
  },
  {
    id: 5,
    title: 'Product Manager',
    company: 'Swiggy',
    location: 'Bengaluru',
    type: 'Hybrid',
    salary: '₹25–35 LPA',
  },
  {
    id: 6,
    title: 'DevOps Engineer',
    company: 'TCS',
    location: 'Mumbai',
    type: 'Full-time',
    salary: '₹6–9 LPA',
  },
  {
    id: 7,
    title: 'Mobile Developer (Flutter)',
    company: 'Zomato',
    location: 'Gurugram',
    type: 'Remote',
    salary: '₹18–24 LPA',
  },
  {
    id: 8,
    title: 'Data Scientist',
    company: 'Fractal',
    location: 'Mumbai',
    type: 'Hybrid',
    salary: '₹14–20 LPA',
  },
  // Duplicates for seamless loop
  {
    id: '1-dup',
    title: 'Frontend Developer (React)',
    company: 'Flipkart',
    location: 'Bengaluru',
    type: 'Hybrid',
    salary: '₹12–18 LPA',
  },
  {
    id: '2-dup',
    title: 'UI/UX Designer',
    company: 'Zoho',
    location: 'Chennai',
    type: 'Full-time',
    salary: '₹6–10 LPA',
  },
  {
    id: '3-dup',
    title: 'Full Stack Developer (MERN)',
    company: 'Razorpay',
    location: 'Bengaluru',
    type: 'Remote',
    salary: '₹15–22 LPA',
  },
  {
    id: '4-dup',
    title: 'Data Analyst',
    company: 'Accenture India',
    location: 'Hyderabad',
    type: 'Full-time',
    salary: '₹8–12 LPA',
  },
  {
    id: '5-dup',
    title: 'Product Manager',
    company: 'Swiggy',
    location: 'Bengaluru',
    type: 'Hybrid',
    salary: '₹25–35 LPA',
  },
  {
    id: '6-dup',
    title: 'DevOps Engineer',
    company: 'TCS',
    location: 'Mumbai',
    type: 'Full-time',
    salary: '₹6–9 LPA',
  },
  {
    id: '7-dup',
    title: 'Mobile Developer (Flutter)',
    company: 'Zomato',
    location: 'Gurugram',
    type: 'Remote',
    salary: '₹18–24 LPA',
  },
  {
    id: '8-dup',
    title: 'Data Scientist',
    company: 'Fractal',
    location: 'Mumbai',
    type: 'Hybrid',
    salary: '₹14–20 LPA',
  },
];

const CATEGORIES = [
  { name: 'Development', icon: '💻', count: '2,340' },
  { name: 'UI/UX', icon: '🎨', count: '890' },
  { name: 'Marketing', icon: '📢', count: '1,120' },
  { name: 'Business', icon: '📊', count: '756' },
  { name: 'Finance', icon: '💰', count: '445' },
];

export default function Home() {
  const [keyword, setKeyword] = useState('');
  const [location, setLocation] = useState('');
  const [activeCategory, setActiveCategory] = useState('Development');

  const handleSearch = (e) => {
    e.preventDefault();
    // UI only - no API
  };

  return (
    <main className="home">
      <section className="hero">
        <div className="hero__container container">
          <h1 className="hero__title">Get The Right Job You Deserve</h1>
          <p className="hero__subtext">
            Find jobs and internships across top Indian companies. Connecting Indian talent with the right opportunities.
          </p>
          <form className="hero__search" onSubmit={handleSearch}>
            <div className="hero__search-row">
              <label htmlFor="keyword" className="visually-hidden">
                Job title or keyword
              </label>
              <input
                id="keyword"
                type="text"
                placeholder="Job title or keyword"
                value={keyword}
                onChange={(e) => setKeyword(e.target.value)}
                className="hero__input"
              />
              <label htmlFor="location" className="visually-hidden">
                Location
              </label>
              <input
                id="location"
                type="text"
                placeholder="City (e.g. Bengaluru, Mumbai)"
                value={location}
                onChange={(e) => setLocation(e.target.value)}
                className="hero__input"
              />
              <button type="submit" className="hero__btn">
                Search
              </button>
            </div>
          </form>
        </div>
      </section>

      <section className="trending" id="jobs">
        <div className="container">
          <h2 className="section__title">Trending Jobs in India</h2>
          <div className="carousel-container">
            <div className="carousel-track">
              {TRENDING_JOBS.map((job) => (
                <JobCard key={job.id} job={job} />
              ))}
            </div>
          </div>
        </div>
      </section>

      <section className="categories">
        <div className="container">
          <h2 className="section__title">Browse by Category</h2>
          <div className="categories__grid">
            {CATEGORIES.map((cat) => (
              <button
                key={cat.name}
                type="button"
                className={`category-card ${activeCategory === cat.name ? 'category-card--active' : ''}`}
                onClick={() => setActiveCategory(cat.name)}
              >
                <span className="category-card__icon" aria-hidden>
                  {cat.icon}
                </span>
                <div className="category-card__content">
                  <h3 className="category-card__name">{cat.name}</h3>
                  <p className="category-card__count">{cat.count} jobs</p>
                </div>
              </button>
            ))}
          </div>
        </div>
      </section>
    </main>
  );
}
