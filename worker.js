addEventListener('fetch', (event) => {
    event.respondWith(handleRequest(event.request, globalThis));
});

// 获取环境变量
const {
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    GOOGLE_REFRESH_TOKEN,
    GOOGLE_ADMIN_EMAIL,
    VERIFICATION_CODE,
    EMAIL_DOMAIN,
    TURNSTILE_SITE_KEY,
    TURNSTILE_SECRET_KEY
} = globalThis;

/**
* 处理传入的请求
* @param {Request} request
* @param {any} env
*/
async function handleRequest(request, env) {
    if (request.method === 'GET') {
        return serveRegistrationForm(EMAIL_DOMAIN, TURNSTILE_SITE_KEY);
    } else if (request.method === 'POST') {
        return handleRegistration(request, EMAIL_DOMAIN, VERIFICATION_CODE, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REFRESH_TOKEN);
    } else {
        return new Response('Method Not Allowed', { status: 405 });
    }
}

/**
* 提供注册表单的 HTML，并集成 Cloudflare Turnstile 验证码
*/
function serveRegistrationForm(emailDomain, turnstileSiteKey) {
    const html = generateRegistrationFormHtml(emailDomain, turnstileSiteKey);
    return new Response(html, {
        headers: { 'Content-Type': 'text/html;charset=UTF-8' },
    });
}

/**
* 生成注册表单的 HTML
*/
function generateRegistrationFormHtml(emailDomain, turnstileSiteKey) {
    return `
<!DOCTYPE html>
<html>
  <head>
    <title>Google Workspace 邮箱注册</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
    <style>
      body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f7f7f7; margin: 0; padding: 0; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
      .container { background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1); max-width: 400px; width: 100%; box-sizing: border-box; }
      h2 { text-align: center; color: #333; font-size: 24px; margin-bottom: 20px; }
      form { display: flex; flex-direction: column; }
      label { font-size: 14px; color: #555; margin-bottom: 6px; }
      input[type="text"], input[type="email"], input[type="password"] { width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; transition: border 0.3s ease; }
      input[type="text"]:focus, input[type="email"]:focus, input[type="password"]:focus { border-color: #4CAF50; outline: none; }
      input[type="submit"] { width: 100%; padding: 12px; background-color: #4CAF50; color: white; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; margin-top: 15px; transition: background-color 0.3s ease; }
      input[type="submit"]:hover { background-color: #45a049; }
      small { font-size: 12px; color: #777; }
      .footer { text-align: center; font-size: 14px; padding-top: 20px; color: #888; }
      .footer a { color: #4CAF50; text-decoration: none; }
      .footer a:hover { text-decoration: underline; }
      @media only screen and (max-width: 600px) { .container { padding: 20px; margin: 10px; } h2 { font-size: 20px; } input[type="text"], input[type="email"], input[type="password"] { padding: 10px; font-size: 14px; } input[type="submit"] { padding: 10px; font-size: 14px; } label { font-size: 12px; } }
    </style>
  </head>
  <body>
    <div class="container">
      <h2>Google Workspace 邮箱注册</h2>
      <form method="POST">
        <label for="firstName">名字:</label>
        <input type="text" id="firstName" name="firstName" required>
        <label for="lastName">姓氏:</label>
        <input type="text" id="lastName" name="lastName" required>
        <label for="username">用户名:</label>
        <input type="text" id="username" name="username" required>
        <small>邮箱后缀将自动添加为 <strong>${escapeHtml(emailDomain)}</strong></small><br><br>
        <label for="password">密码:</label>
        <input type="password" id="password" name="password" required>
        <label for="recoveryEmail">恢复邮箱:</label>
        <input type="email" id="recoveryEmail" name="recoveryEmail" required>
        <label for="verificationCode">验证码:</label>
        <input type="text" id="verificationCode" name="verificationCode" required>
        <div class="cf-turnstile" data-sitekey="${turnstileSiteKey}"></div>
        <input type="submit" value="注册">
      </form>
    </div>
  </body>
</html>
`;
}

/**
* 处理注册表单提交，并验证 Cloudflare Turnstile 图形验证码
*/
async function handleRegistration(request, emailDomain, verificationCode, googleClientId, googleClientSecret, googleRefreshToken) {
    const formData = await request.formData();
    const firstName = formData.get('firstName');
    const lastName = formData.get('lastName');
    const username = formData.get('username');
    const password = formData.get('password');
    const recoveryEmail = formData.get('recoveryEmail');
    const verificationCodeInput = formData.get('verificationCode');
    const captchaToken = formData.get('cf-turnstile-response');

    // 1. 先校验图形验证码
    const isHuman = await verifyTurnstile(captchaToken);
    if (!isHuman) {
        return new Response('图形验证码校验失败，请重试。', { status: 400 });
    }

    // 2. 验证输入
    if (!firstName || !lastName || !username || !password || !recoveryEmail || !verificationCodeInput) {
        return createResponse('所有字段都是必填的。', 400);
    }

    if (!validateEmail(recoveryEmail)) {
        return createResponse('恢复邮箱格式不正确。', 400);
    }

    if (verificationCodeInput !== verificationCode) {
        return createResponse('验证码错误。', 400);
    }

    const email = `${username}${emailDomain}`;

    if (!email.endsWith(emailDomain)) {
        return new Response(`邮箱后缀必须是 ${emailDomain}。`, { status: 400 });
    }

    try {
        const accessToken = await getAccessToken(googleClientId, googleClientSecret, googleRefreshToken);

        const user = {
            name: {
                givenName: firstName,
                familyName: lastName,
            },
            password: password,
            primaryEmail: email,
            recoveryEmail: recoveryEmail,
        };

        const response = await fetch('https://admin.googleapis.com/admin/directory/v1/users', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(user),
        });

        if (response.ok) {
            const redirectHtml = generateSuccessHtml(email);
            return new Response(redirectHtml, {
                headers: { 'Content-Type': 'text/html;charset=UTF-8' },
            });
        } else {
            const error = await response.json();
            return new Response(`注册失败: ${error.error.message}`, { status: 500 });
        }
    } catch (error) {
        return new Response(`内部错误: ${error.message}`, { status: 500 });
    }
}

/**
* 生成注册成功后的 HTML
*/
function generateSuccessHtml(email) {
    return `
<!DOCTYPE html>
<html>
  <head>
    <title>注册成功</title>
    <meta http-equiv="refresh" content="3;url=https://accounts.google.com/ServiceLogin?Email=${encodeURIComponent(email)}&continue=https://mail.google.com/mail/">
    <style>
      body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f7f7f7; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
      .message { background-color: white; padding: 20px; border-radius: 10px; box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1); text-align: center; }
    </style>
  </head>
  <body>
    <div class="message">
      <h2>注册成功！</h2>
      <p>用户 <strong>${escapeHtml(email)}</strong> 已成功创建。</p>
      <p>正在跳转到谷歌登录页面...</p>
    </div>
  </body>
</html>
`;
}

/**
* 获取 Google API 访问令牌
*/
async function getAccessToken(googleClientId, googleClientSecret, googleRefreshToken) {
    const tokenEndpoint = 'https://oauth2.googleapis.com/token';

    const params = new URLSearchParams();
    params.append('client_id', googleClientId);
    params.append('client_secret', googleClientSecret);
    params.append('refresh_token', googleRefreshToken);
    params.append('grant_type', 'refresh_token');

    const tokenResponse = await fetch(tokenEndpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: params,
    });

    if (!tokenResponse.ok) {
        const error = await tokenResponse.text();
        throw new Error(`无法获取访问令牌: ${error}`);
    }

    const tokenData = await tokenResponse.json();
    return tokenData.access_token;
}

/**
* 转义 HTML 特殊字符，防止 XSS 攻击
* @param {string} unsafe
* @returns {string}
*/
function escapeHtml(unsafe) {
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;")
}

/**
* 验证邮箱格式
* @param {string} email
* @returns {boolean}
*/
function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    return re.test(email)
}

/**
 * 验证 Cloudflare Turnstile 验证码
 * @param {string} token - 前端提交的 Turnstile token
 * @returns {Promise<boolean>} true 表示验证通过，否则验证失败
 */
async function verifyTurnstile(token) {
    const secretKey = TURNSTILE_SECRET_KEY;

    if (!token) {
        return false;
    }

    const url = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
    const body = new URLSearchParams();
    body.append("secret", secretKey);
    body.append("response", token);

    try {
        const resp = await fetch(url, {
            method: "POST",
            body,
        });
        const data = await resp.json();
        return data.success === true;
    } catch (err) {
        console.error('Error verifying Turnstile token:', err);
        return false;
    }
}

function createResponse(message, status = 200) {
    return new Response(message, { status });
}
