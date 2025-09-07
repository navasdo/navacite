import { jwtVerify } from 'jose';

// This function is the middleware that will run on specified paths
export async function middleware(request) {
    // Get the pathname from the request URL (e.g., '/', '/dashboard.html')
    const { pathname } = request.nextUrl;

    // --- Define Public Paths ---
    // These are the pages a user can visit without being logged in.
    const publicPaths = [
        '/login.html',
        '/apply.html',
        '/api/login', // The API endpoint for logging in must be public
        '/navacite.ico' // Your favicon should be public
    ];

    // Check if the requested path is one of the public paths.
    // If it is, we do nothing and let the request proceed.
    if (publicPaths.some(path => pathname === path)) {
        // By returning nothing, we allow the request to continue.
        return; 
    }
    
    // --- Authentication Check ---
    // Try to get the authentication token from the user's cookies.
    const tokenCookie = request.cookies.get('token');
    const loginUrl = new URL('/login.html', request.url);
    const JWT_SECRET = process.env.JWT_SECRET;
    
    // If the token cookie doesn't exist or is empty, redirect to login.
    if (!tokenCookie || !tokenCookie.value) {
        return Response.redirect(loginUrl);
    }
    
    // If a token exists, we must verify it.
    try {
        if (!JWT_SECRET) {
             throw new Error('JWT_SECRET environment variable is not set on Vercel.');
        }
        // Create the secret key for verification.
        const secret = new TextEncoder().encode(JWT_SECRET);
        
        // Verify the token. If it's invalid, this will throw an error.
        await jwtVerify(tokenCookie.value, secret);
        
        // If jwtVerify() succeeds, the token is valid. Allow the request to proceed.
        return;
        
    } catch (err) {
        // If verification fails (token is expired, malformed, etc.), redirect to login.
        console.log('JWT Verification Failed:', err.message);
        
        // Create a redirect response.
        const response = Response.redirect(loginUrl);
        
        // IMPORTANT: Clear the invalid cookie from the user's browser.
        // We do this by setting a cookie with the same name and an expiration date in the past.
        response.headers.append('Set-Cookie', 'token=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT');
        
        return response;
    }
}

// --- Path Matching Configuration ---
// This tells Vercel which requests should trigger the middleware.
export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones that end with a file extension
     * for common static assets like images or fonts. This ensures the middleware
     * runs on all page routes (e.g., '/', '/dashboard.html').
     */
    '/((?!.*\\.(?:ico|png|jpg|jpeg|gif|svg|webp|woff2)$).*)',
  ],
};

