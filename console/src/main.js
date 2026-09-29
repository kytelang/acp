import { createApp } from 'vue'
import { createPinia } from 'pinia'
import App from './App.vue'
import { router } from './router.js'
import './style.css'

// Apply the persisted theme before mount to avoid a flash.
if (localStorage.getItem('acp-theme') === 'light') document.documentElement.classList.add('light')

createApp(App).use(createPinia()).use(router).mount('#app')
