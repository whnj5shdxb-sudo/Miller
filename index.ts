// After removing the duplicate handler
// Removed duplicate POST /api/auth/login route handler that performs plaintext password comparison
// Keeping the earlier loginHandler-based route registration

app.post('/api/auth/login', loginHandler);