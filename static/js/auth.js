/**
 * 前端统一认证模块
 * - 在每个 HTML 页面 <head> 引入本文件
 * - 自动检查登录态，未登录跳 login.html
 * - 自动给所有 fetch 请求加上 Authorization 头
 */

(function() {
    'use strict';

    // 登录页和改密页不需要鉴权
    var path = location.pathname;
    var publicPaths = [
        '/static/login.html',
        '/static/change-password.html'
    ];
    if (publicPaths.indexOf(path) >= 0) return;

    var token = null;
    try { token = localStorage.getItem('auth_token'); } catch (e) {}

    if (!token) {
        location.replace('/static/login.html');
        return;
    }

    // 全局标记已登录
    window.AUTH_TOKEN = token;

    // 给 fetch 包装一层：自动带 Authorization
    var originalFetch = window.fetch;
    window.fetch = function(url, options) {
        options = options || {};
        options.headers = options.headers || {};
        // 仅对 /api 请求加 header
        try {
            var u = (typeof url === 'string') ? url : (url && url.url) || '';
            if (u.indexOf('/api/') === 0 || u.indexOf('/api/') > -1) {
                if (!options.headers['Authorization'] && !options.headers['authorization']) {
                    options.headers['Authorization'] = 'Bearer ' + token;
                }
            }
        } catch (e) {}
        return originalFetch(url, options);
    };

    // 异步检查 token 有效性（用 /api/me）
    // 如果失效，跳登录页
    originalFetch('/api/me', { headers: { 'Authorization': 'Bearer ' + token } })
        .then(function(r) {
            if (r.status === 401) {
                try { localStorage.removeItem('auth_token'); localStorage.removeItem('auth_user'); } catch (e) {}
                location.replace('/static/login.html');
            } else if (r.ok) {
                return r.json();
            }
        })
        .then(function(user) {
            if (user) {
                window.AUTH_USER = user;
                try { localStorage.setItem('auth_user', JSON.stringify(user)); } catch (e) {}
                // 如果用户必须改密码，强制跳到改密页
                if (user.must_change_password) {
                    location.replace('/static/change-password.html?first=1');
                }
            }
        })
        .catch(function() {});

    // 暴露登出函数
    window.authLogout = function() {
        originalFetch('/api/logout', {
            method: 'POST',
            headers: { 'Authorization': 'Bearer ' + token }
        }).finally(function() {
            try { localStorage.removeItem('auth_token'); localStorage.removeItem('auth_user'); } catch (e) {}
            document.cookie = 'auth_token=; path=/; max-age=0';
            location.replace('/static/login.html');
        });
    };

    // 暴露获取当前用户信息函数
    window.authGetUser = function() {
        try { return JSON.parse(localStorage.getItem('auth_user') || 'null'); } catch (e) { return null; }
    };
})();