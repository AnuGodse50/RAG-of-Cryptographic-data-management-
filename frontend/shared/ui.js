const UI = {
    showToast(message, type = 'success') {
        let container = document.querySelector('.toast-container');
        if (!container) {
            container = document.createElement('div');
            container.className = 'toast-container';
            document.body.appendChild(container);
        }
        const toast = document.createElement('div');
        toast.className = 'toast ' + type;
        toast.textContent = message;
        container.appendChild(toast);
        setTimeout(() => toast.remove(), 3000);
    },
    renderNav() {
        const nav = document.createElement('nav');
        nav.className = 'navbar';
        nav.innerHTML = \
            <div class="navbar-brand">AEGIS-VERITAS</div>
            <div class="navbar-nav">
                <a href="cases.html">Dashboard</a>
                <a href="upload.html">Upload Evidence</a>
                <a href="#" id="logoutBtn">Logout</a>
            </div>
        \;
        document.body.insertBefore(nav, document.body.firstChild);
        document.getElementById('logoutBtn')?.addEventListener('click', (e) => {
            e.preventDefault();
            localStorage.removeItem('access_token');
            window.location.href = 'login.html';
        });
    }
};
window.UI = UI;
document.addEventListener('DOMContentLoaded', () => {
    if(!window.location.pathname.endsWith('login.html')) UI.renderNav();
});
