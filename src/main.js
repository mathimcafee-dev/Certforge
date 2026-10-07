import { start } from './ui/app.js';
if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start); else start();
