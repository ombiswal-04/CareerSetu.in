import jwt from 'jsonwebtoken';
import User from '@/models/User';
import connectDB from '@/lib/db';

function getJWTSecret() {
    const secret = process.env.JWT_SECRET;
    if (!secret) {
        throw new Error('Please define JWT_SECRET in .env.local');
    }
    return secret;
}

export function generateToken(id) {
    return jwt.sign({ id }, getJWTSecret(), { expiresIn: '30d' });
}

export function verifyToken(token) {
    try {
        return jwt.verify(token, getJWTSecret());
    } catch (error) {
        return null;
    }
}

export async function getUserFromRequest(request) {
    const authHeader = request.headers.get('authorization');

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return null;
    }

    const token = authHeader.split(' ')[1];
    const decoded = verifyToken(token);

    if (!decoded) {
        return null;
    }

    await connectDB();
    const user = await User.findById(decoded.id).select('-password');
    return user;
}

export function unauthorizedResponse(message = 'Not authorized') {
    return Response.json({ message }, { status: 401 });
}

export function adminOnlyResponse() {
    return Response.json({ message: 'Not authorized as admin' }, { status: 401 });
}
