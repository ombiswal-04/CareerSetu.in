# Job Tracker

A comprehensive MERN stack application for tracking job applications, managing job postings, and connecting talents with opportunities. This platform serves both job seekers and administrators with dedicated dashboards and functionalities.

## 🚀 Features

### For Users (Job Seekers)
- **Browse Jobs**: View available job listings with filtering options.
- **Job Application**: Apply to jobs directly or via external links.
- **My Work**: Track status of applied jobs.
- **Profile Management**: Update user profile and preferences.
- **Authentication**: Secure Login and Registration.

### For Admins
- **Admin Dashboard**: Overview of platform statistics.
- **Job Management**: Create, Edit, and Delete job postings.
- **Talent Management**: Browse and manage registered talents.
- **Hiring**: Manage hiring processes.

## 🛠️ Tech Stack

### Frontend
- **React** (Vite)
- **React Router** for navigation
- **Context API** for state management (Auth, Theme)
- **CSS** for styling

### Backend
- **Node.js** & **Express.js**
- **MongoDB** with **Mongoose**
- **JWT** for Authentication
- **Multer** for file uploads

## 📦 Installation & Setup

### Prerequisites
- [Node.js](https://nodejs.org/) installed
- [MongoDB](https://www.mongodb.com/) installed or a MongoDB Atlas connection string

### 1. Clone the Repository
```bash
git clone https://github.com/ombiswal-04/job-tracker.git
cd job-tracker
```

### 2. Backend Setup
Navigate to the backend directory and install dependencies:
```bash
cd backend
npm install
```

Create a `.env` file in the `backend` directory with the following variables:
```env
PORT=5000
MONGO_URI=your_mongodb_connection_string
JWT_SECRET=your_jwt_secret_key
```

Start the backend server:
```bash
npm start
```
The server will run on `http://localhost:5000`.

### 3. Frontend Setup
Open a new terminal, navigate to the frontend directory, and install dependencies:
```bash
cd frontend
npm install
```

Create a `.env` file in the `frontend` directory (if required for API URL configuration):
```env
VITE_API_URL=http://localhost:5000
```
*(Note: Check file `src/config/api.js` or similar if the base URL is hardcoded or Env variable driven)*

Start the frontend development server:
```bash
npm run dev
```
The application will run on `http://localhost:5173` (or the port shown in your terminal).

## 🚀 Deployment

- **Frontend**: Can be deployed on Vercel, Netlify, or similar platforms.
- **Backend**: Can be deployed on Render, Railway, or Heroku.

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!

## 📄 License

This project is licensed under the ISC License.
