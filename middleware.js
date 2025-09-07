// --- ULTIMATE DIAGNOSTIC TEST ---
// This middleware has only one purpose: to prove if a redirect is possible.

export async function middleware(request) {
    const { pathname } = request.nextUrl;

    // Rule: If the user is trying to access the homepage ('/'),
    // unconditionally redirect them to the login page.
    if (pathname === '/') {
        console.log("DIAGNOSTIC: Forcing redirect from '/' to '/login.html'");
        const loginUrl = new URL('/login.html', request.url);
        
        return new Response(null, {
            status: 307, // Temporary Redirect
            headers: {
                'Location': loginUrl.toString()
            }
        });
    }

    // For any other path, do nothing.
    console.log(`DIAGNOSTIC: Path is '${pathname}', allowing pass-through.`);
    return; 
}

// We use the same robust matcher to ensure this code runs.
export const config = {
  matcher: [
    '/((?!api|_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)',
  ],
};

