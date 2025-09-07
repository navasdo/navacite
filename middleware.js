import { jwtVerify } from 'jose';

export async function middleware(request) {
    console.log(`Middleware triggered for path: ${request.nextUrl.pathname}`);

    const { pathname } = request.nextUrl;

    // --- THE FIX ---
    // This list now includes both the direct .html files in the root
    // and their potential "clean URL" equivalents, making it more robust.
    const publicPaths = [
        '/login.html',
        '/login',
        '/apply.html',
        '/apply',
        '/api/login',
    ];

    if (publicPaths.includes(pathname)) {
        return; // Allow request to proceed
    }

    const token = request.cookies.get('token')?.value;
    const loginUrl = new URL('/login.html', request.url);

    // If no token is found, perform the redirect.
    if (!token) {
        console.log(`No token for ${pathname}. Redirecting...`);
        return new Response(null, {
            status: 307, // Temporary Redirect
            headers: {
                'Location': loginUrl.toString()
            }
        });
    }

    // If a token is found, verify it.
    try {
        const JWT_SECRET = process.env.JWT_SECRET;
        if (!JWT_SECRET) throw new Error('JWT_SECRET not set.');
        
        const secret = new TextEncoder().encode(JWT_SECRET);
        await jwtVerify(token, secret);
        
        // Token is valid, let the user proceed.
        return;

    } catch (err) {
        console.log(`Token verification failed for ${pathname}. Redirecting...`);
        const response = new Response(null, {
            status: 307, // Temporary Redirect
            headers: {
                'Location': loginUrl.toString()
            }
        });
        // Clear the bad cookie
        response.headers.set('Set-Cookie', 'token=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT');
        return response;
    }
}

// The matcher is correct and does not need to be changed.
export const config = {
  matcher: [
    '/((?!api|_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)',
  ],
};

