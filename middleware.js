import { jwtVerify } from 'jose';

export async function middleware(request) {
    const tokenCookie = request.cookies.get('token');
    const { pathname } = new URL(request.url);

    const JWT_SECRET = process.env.JWT_SECRET;

    // Define public paths that don't require authentication
    const publicPaths = ['/login.html', '/apply.html', '/api/login'];
    
    // If the path is public, let the request go through.
    if (publicPaths.some(path => pathname.startsWith(path))) {
        return; // This is the equivalent of NextResponse.next()
    }
    
    const loginUrl = new URL('/login.html', request.url);

    // If there's no token cookie, redirect to the login page.
    if (!tokenCookie || !tokenCookie.value) {
        return Response.redirect(loginUrl);
    }
    
    // Verify the token
    try {
        if (!JWT_SECRET) {
            throw new Error('JWT_SECRET environment variable is not set on Vercel.');
        }
        const secret = new TextEncoder().encode(JWT_SECRET);
        await jwtVerify(tokenCookie.value, secret);
        
        // If token is valid, allow the request to proceed to the originally requested page.
        return;
    } catch (err) {
        // If the token is invalid (expired, malformed, etc.), redirect to login.
        console.log('JWT Verification Error:', err.message);
        
        const response = Response.redirect(loginUrl);
        
        // Clear the invalid cookie by setting its expiration date to the past.
        response.headers.append('Set-Cookie', 'token=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT');
        
        return response;
    }
}

// The matcher config remains the same, it tells the middleware which paths to run on.
export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     * - and image files in the public folder (e.g., .png, .jpg)
     */
    '/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)',
  ],
}

