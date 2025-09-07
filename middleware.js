import { NextResponse } from 'next/server';
import { jwtVerify } from 'jose';

// This function can be marked `async` if using `await` inside
export async function middleware(request) {
    const tokenCookie = request.cookies.get('token');
    const { pathname } = request.nextUrl;

    const JWT_SECRET = process.env.JWT_SECRET;

    // Define public paths that don't require authentication
    const publicPaths = ['/login.html', '/apply.html', '/api/login'];
    
    if (publicPaths.some(path => pathname.startsWith(path))) {
        return NextResponse.next();
    }
    
    // If there's no token, redirect to login
    if (!tokenCookie || !tokenCookie.value) {
        const url = request.nextUrl.clone();
        url.pathname = '/login.html';
        return NextResponse.redirect(url);
    }
    
    // Verify the token
    try {
        const secret = new TextEncoder().encode(JWT_SECRET);
        await jwtVerify(tokenCookie.value, secret);
        // If token is valid, proceed
        return NextResponse.next();
    } catch (err) {
        // If token is invalid, redirect to login
        console.log('JWT Verification Error:', err.message);
        const url = request.nextUrl.clone();
        url.pathname = '/login.html';
        const response = NextResponse.redirect(url);
        // Clear the invalid cookie
        response.cookies.delete('token');
        return response;
    }
}

// See "Matching Paths" below to learn more
export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     * - and image files in the public folder
     */
    '/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)',
  ],
}
