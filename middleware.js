import { jwtVerify } from 'jose';

export async function middleware(request) {
    // --- DIAGNOSTIC LOG ---
    // This is the most important line. It will tell us if the middleware is running.
    console.log(`Middleware triggered for path: ${request.nextUrl.pathname}`);

    const { pathname } = request.nextUrl;

    // --- Define Public File Paths ---
    const publicPaths = [
        '/login.html',
        '/apply.html',
        '/api/login',
    ];

    // --- Gate 1: Check for Public Paths ---
    if (publicPaths.includes(pathname)) {
        return; // Allow request to proceed
    }

    // --- Gate 2: Protect Everything Else ---
    const token = request.cookies.get('token')?.value;
    const loginUrl = new URL('/login.html', request.url);

    if (!token) {
        console.log(`No token found for path ${pathname}. Redirecting to login.`);
        return Response.redirect(loginUrl);
    }

    // --- Gate 3: Verify Token ---
    try {
        const JWT_SECRET = process.env.JWT_SECRET;
        if (!JWT_SECRET) throw new Error('JWT_SECRET not set.');
        
        const secret = new TextEncoder().encode(JWT_SECRET);
        await jwtVerify(token, secret);
        
        // Token is valid, proceed to the requested page.
        return;

    } catch (err) {
        console.log(`Token verification failed for path ${pathname}. Redirecting.`);
        const response = Response.redirect(loginUrl);
        response.headers.set('Set-Cookie', 'token=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT');
        return response;
    }
}

// --- Path Matching Configuration (Simplified & More Robust) ---
// This matcher tells Vercel to run the middleware on ALL paths,
// except for internal Next.js assets, API routes (handled in code),
// and common static file types. This is more reliable.
export const config = {
  matcher: [
    '/((?!api|_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)',
  ],
};

