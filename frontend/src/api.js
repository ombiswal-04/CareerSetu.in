import axios from 'axios';

const API = axios.create({
    baseURL: import.meta.env.VITE_API_URL || 'http://localhost:5000',
});

// Add a request interceptor to attach the token if it exists (optional but good practice)
API.interceptors.request.use((req) => {
    // If you store token in localStorage, you can attach it here
    // const user = JSON.parse(localStorage.getItem('user'));
    // if (user?.token) {
    //     req.headers.Authorization = `Bearer ${user.token}`;
    // }
    return req;
});

export default API;
