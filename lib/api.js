import axios from 'axios';

const API = axios.create({
    baseURL: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5000',
    withCredentials: true,
});

// Add a request interceptor to attach the token if it exists
API.interceptors.request.use((req) => {
    if (typeof window !== 'undefined') {
        const user = localStorage.getItem('user');
        if (user) {
            try {
                const userData = JSON.parse(user);
                if (userData?.token) {
                    req.headers.Authorization = `Bearer ${userData.token}`;
                }
            } catch (e) {
                console.error('Failed to parse user token', e);
            }
        }
    }
    return req;
});

export default API;
