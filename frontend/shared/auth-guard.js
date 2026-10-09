(function() {
    const token = localStorage.getItem('access_token');
    const isLoginPage = window.location.pathname.endsWith('login.html');
    if (!token && !isLoginPage) { window.location.href = 'login.html'; }
    if (token && isLoginPage) { window.location.href = 'cases.html'; }
})();
