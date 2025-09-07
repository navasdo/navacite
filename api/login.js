import jwt from 'jsonwebtoken';
import { serialize } from 'cookie';

export default async function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ message: 'Method Not Allowed' });
    }

    const { username, password } = req.body;

    // Get credentials and secret from environment variables
    const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
    const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
    const JWT_SECRET = process.env.JWT_SECRET;

    if (!ADMIN_USERNAME || !ADMIN_PASSWORD || !JWT_SECRET) {
        console.error('Environment variables are not set!');
        return res.status(500).json({ message: 'Server configuration error.' });
    }
    
    // Check if credentials are correct
    if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
        // Create a JWT
        const token = jwt.sign(
            { username: username, authorized: true },
            JWT_SECRET,
            { expiresIn: '1d' } // Token expires in 1 day
        );

        // Serialize the cookie
        const cookie = serialize('token', token, {
            httpOnly: true,       // Prevents access from client-side scripts
            secure: process.env.NODE_ENV !== 'development', // Use secure cookies in production
            sameSite: 'strict',   // CSRF protection
            maxAge: 60 * 60 * 24, // 1 day in seconds
            path: '/',            // Cookie is available for the entire site
        });

        // Set the cookie in the response header
        res.setHeader('Set-Cookie', cookie);
        
        // Send a success response
        return res.status(200).json({ message: 'Login successful' });
    }

    // If credentials are wrong
    return res.status(401).json({ message: 'Invalid username or password' });
}

