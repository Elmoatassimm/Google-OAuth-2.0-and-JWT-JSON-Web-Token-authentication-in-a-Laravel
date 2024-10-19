import { defineConfig } from 'vite';
import laravel from 'laravel-vite-plugin';

export default defineConfig({
    plugins: [
        laravel({
            input: ['resources/css/app.css', '../frontend/src/App.js'],
            refresh: true,
        }),
    ],
});
