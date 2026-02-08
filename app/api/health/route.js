// Simple health check endpoint
export async function GET() {
    return Response.json({ status: 'ok', message: 'API is working' });
}
