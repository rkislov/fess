export default defineNuxtConfig({
  ssr: false,
  css: ['~/assets/css/app.css'],
  modules: ['@nuxtjs/tailwindcss'],
  tailwindcss: {
    config: {
      theme: {
        extend: {
          fontFamily: {
            sans: ['DM Sans', 'system-ui', 'sans-serif'],
          },
        },
      },
    },
  },
  nitro: {
    preset: 'static',
  },
  runtimeConfig: {
    public: {
      apiBase: process.env.NUXT_PUBLIC_API_BASE || '/api/v1',
      /** Set to "0" / "false" to skip the login screen (e.g. behind corporate SSO). */
      uiAuthEnabled: process.env.NUXT_PUBLIC_UI_AUTH_ENABLED ?? 'true',
      uiUser: process.env.NUXT_PUBLIC_UI_USER || 'admin',
      uiPassword: process.env.NUXT_PUBLIC_UI_PASSWORD || 'fessfess',
    },
  },
  app: {
    head: {
      title: 'FESS — Frontend Security Server',
      meta: [
        { name: 'viewport', content: 'width=device-width, initial-scale=1' },
        { name: 'color-scheme', content: 'dark light' },
      ],
      script: [
        {
          innerHTML:
            "(function(){try{var p=localStorage.getItem('fess-ui-theme')||'system';var d=p==='dark'||(p!=='light'&&(!window.matchMedia||window.matchMedia('(prefers-color-scheme: dark)').matches));var r=document.documentElement;r.classList.add(d?'theme-dark':'theme-light');r.classList.remove(d?'theme-light':'theme-dark');r.style.colorScheme=d?'dark':'light'}catch(e){}})()",
          tagPosition: 'head',
        },
      ],
      link: [
        { rel: 'icon', type: 'image/jpeg', href: '/brand/splash.jpg' },
        { rel: 'preconnect', href: 'https://fonts.googleapis.com' },
        { rel: 'preconnect', href: 'https://fonts.gstatic.com', crossorigin: '' },
        {
          rel: 'stylesheet',
          href: 'https://fonts.googleapis.com/css2?family=DM+Sans:ital,opsz,wght@0,9..40,400;0,9..40,500;0,9..40,600;0,9..40,700;1,9..40,400&display=swap',
        },
      ],
    },
  },
  compatibilityDate: '2024-11-01',
})
