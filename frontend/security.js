// CSRF protection for state-changing API calls.  The token is deliberately a
// non-HttpOnly cookie so same-origin JavaScript can echo it in a custom header;
// browsers do not permit an attacker on another origin to read it.
(function () {
    function getCookie(name) {
        const prefix = `${name}=`;
        return document.cookie.split(';').map(value => value.trim())
            .find(value => value.startsWith(prefix))?.slice(prefix.length) || '';
    }

    if (!getCookie('csrf_token')) {
        const bytes = new Uint8Array(32);
        crypto.getRandomValues(bytes);
        const token = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
        const secure = location.protocol === 'https:' ? '; Secure' : '';
        document.cookie = `csrf_token=${token}; Path=/; SameSite=Strict${secure}`;
    }

    const nativeFetch = window.fetch.bind(window);
    window.fetch = function (input, init = {}) {
        const method = (init.method || 'GET').toUpperCase();
        if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) return nativeFetch(input, init);
        const headers = new Headers(init.headers || {});
        headers.set('X-CSRF-Token', getCookie('csrf_token'));
        return nativeFetch(input, {...init, headers});
    };
}());
