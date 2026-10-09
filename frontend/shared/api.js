const API = {
    async fetch(url, options = {}) {
        const token = localStorage.getItem('access_token');
        const headers = { ...options.headers };
        if (token) { headers['Authorization'] = 'Bearer ' + token; }
        if (!(options.body instanceof FormData)) { headers['Content-Type'] = 'application/json'; }
        
        try {
            const response = await fetch(url, { ...options, headers });
            if (response.status === 401) {
                localStorage.removeItem('access_token');
                window.location.href = 'login.html';
                throw new Error('Unauthorized');
            }
            return response;
        } catch (error) {
            console.error('API Error:', error);
            throw error;
        }
    }
};
window.API = API;
