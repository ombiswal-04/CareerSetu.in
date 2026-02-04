# CareerSetu.in

CareerSetu.in is a modern full-stack job portal web application built using the MERN stack. It enables job seekers to discover and track job applications while allowing administrators to manage job postings, applicants, and hiring workflows through role-based dashboards.

The platform supports secure authentication, resume uploads, application tracking, and real-world recruitment workflows, making it suitable for both learning and portfolio showcasing.

## 🌐 Live Demo

Hosted on:
🔗 **[CareerSetu.in](https://ombiswal-04.github.io/CareerSetu.in/)** (GitHub Pages)

## ⭐ Like the Project?

If you find this project useful or interesting, consider starring 🌟 the repository to show your support.
It motivates me to keep improving the project and adding more features.
👉 [Give it a Star on GitHub](https://github.com/ombiswal-04/job-tracker)

## 📦 Tech Stack

### Frontend
- **React** (Vite)
- **React Router DOM**
- **Context API** (Auth & Theme)
- **CSS**

### Backend
- **Node.js**
- **Express.js**
- **MongoDB** with **Mongoose**

### Authentication
- **JWT-based Authentication**

### File Upload
- **Multer** (Resume Uploads)

### Hosting
- **Full Stack (Recommended)**: Vercel (Frontend + Backend)
- **Alternative**: GitHub Pages (Frontend) + Render (Backend)

## 🚀 Features

### 🧾 User Authentication
- Signup and login
- JWT-based secure authentication
- Role-based access (User / Admin)

### 👤 Job Seekers
- Browse and filter job listings
- Apply to jobs (internal or external links)
- Track application status (Applied, Interview, Accepted, Rejected)
- Upload and manage resumes
- Manage profile and preferences

### 🛠️ Admin
- Admin dashboard overview
- Create, update, and delete job postings
- View and manage applicants
- Schedule interviews
- Control hiring workflows

## ⚙️ Getting Started Locally

### 1. Clone the Repository
```bash
git clone https://github.com/ombiswal-04/job-tracker.git
cd job-tracker
```

### 2. Install Dependencies

**Backend**
```bash
cd backend
npm install
```

**Frontend**
```bash
cd ../frontend
npm install
```

### 3. Create Environment Files

✅ **Backend .env** (inside `/backend`)
```env
PORT=5000
MONGO_URI=your_mongodb_connection_string
JWT_SECRET=your_jwt_secret
```

✅ **(Optional) Frontend .env** (inside `/frontend`)
```env
VITE_API_URL=http://localhost:5000
```
➡️ ***Make sure your MongoDB database is running (local or Atlas).***

### 4. Start the App

**Run Backend**
```bash
cd backend
npm start
```

**Run Frontend**
```bash
cd ../frontend
npm run dev
```

The app will run on:
- **Frontend**: `http://localhost:5173`
- **Backend**: `http://localhost:5000`

## 🌐 Deployment Notes

### ⚙️ CORS Settings (Backend – Production)
```javascript
app.use(cors({
  origin: "https://your-frontend-url",
  credentials: true
}));
```

### 🔐 JWT Usage
- Tokens are generated on login
- Protected routes for users and admins
- Role-based authorization enforced on backend

## 📁 Project Structure

```
CareerSetu/
├── backend/
│   ├── config/
│   ├── controllers/
│   ├── middleware/
│   ├── models/
│   ├── routes/
│   ├── uploads/
│   └── server.js
│
├── frontend/
│   ├── components/
│   ├── pages/
│   ├── context/
│   └── App.jsx
│
├── README.md
```

## 👥 Author

Built by **Om Biswal** 💻
Open to contributions, suggestions, and collaboration.

## 📝 License

This project is licensed under the **ISC License**.
You are free to use, modify, and distribute this software under the terms of the license.
