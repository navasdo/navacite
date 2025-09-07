import { jwtVerify } from 'jose';

export async function middleware(request) {
    const { pathname } = request.nextUrl;

    // --- Define Public File Paths ---
    // Based on your site's structure, these are the ONLY paths
    // that can be accessed without a login token.
    const publicPaths = [
        '/login.html',
        '/apply.html',
        '/api/login',    // The API endpoint for authentication
        '/navacite.ico'  // The site favicon
    ];

    // --- Gate 1: Check for Public Paths ---
    // If the user is requesting one of the exact public paths,
    // let the request proceed without any checks.
    if (publicPaths.includes(pathname)) {
        return;
    }

    // --- Gate 2: Protect Everything Else ---
    // If the path was not in the public list, it is a protected route.
    // We must now verify the user has a valid token.
    const token = request.cookies.get('token')?.value;
    const loginUrl = new URL('/login.html', request.url);

    // If there is no token, redirect to the login page immediately.
    if (!token) {
        return Response.redirect(loginUrl);
    }

    // If a token exists, we must verify it.
    try {
        const JWT_SECRET = process.env.JWT_SECRET;
        if (!JWT_SECRET) {
            throw new Error('JWT_SECRET environment variable is not set on Vercel.');
        }
        const secret = new TextEncoder().encode(JWT_SECRET);
        await jwtVerify(token, secret);
        
        // If jwtVerify() succeeds, the token is valid.
        // The user is authenticated and can access the protected route.
        return;

    } catch (err) {
        // If jwtVerify() fails, the token is invalid (expired, malformed, etc.).
        // Redirect to the login page and clear the bad cookie from the browser.
        console.log('JWT Verification Failed, redirecting to login:', err.message);
        const response = Response.redirect(loginUrl);
        response.headers.set('Set-Cookie', 'token=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT');
        return response;
    }
}

// --- Path Matching Configuration ---
// This config correctly runs the middleware on page routes 
// while ignoring static file assets (e.g. images, fonts).
export const config = {
  matcher: [
    '/((?!.*\\.(?:ico|png|jpg|jpeg|gif|svg|webp|woff2)$).*)',
  ],
};

