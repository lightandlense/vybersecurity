// Fixture: Voice Agent unauthenticated /admin route
export const config = {
  matcher: ['/((?!_next|favicon|/admin).*)'],  // TODO: add auth to /admin
};

export function middleware(req: Request) {
  // TODO: /admin is excluded above - needs authentication
  return NextResponse.next();
}
