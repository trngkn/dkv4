module.exports = {
  apps: [
    {
      // === Xvfb - Màn hình ảo cho Chrome ===
      name: 'xvfb',
      script: '/usr/bin/Xvfb',
      args: ':99 -screen 0 1280x720x24 -nolisten tcp',
      autorestart: true,
      watch: false,
      max_restarts: 10,
      restart_delay: 2000,
    },
    {
      // === EzSolver - Bypass Cloudflare Turnstile ===
      name: 'ezsolver',
      script: '/usr/bin/python3.11',
      args: '-u service.py',
      cwd: './EzSolver',
      env: {
        DISPLAY: ':99',
        MAX_WORKERS: '2',
      },
      autorestart: true,
      watch: false,
      max_restarts: 50,
      restart_delay: 5000,
    },
    {
      // === API Server - PhatNguoi tra cứu ===
      name: 'phatnguoi-api',
      script: 'phatnguoi_api.js',
      env: {
        PORT: 3001,
        NODE_ENV: 'production',
      },
      autorestart: true,
      watch: false,
      max_restarts: 50,
      restart_delay: 3000,
    }
  ]
};
