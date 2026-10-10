import './app.css';
import { mount } from 'svelte';
import App from './App.svelte';

const releaseVersion = import.meta.env.VITE_NETP2P_VERSION ?? 'dev';
document.documentElement.dataset.netp2pVersion = releaseVersion;
document.title = `NetP2P ${releaseVersion}`;

mount(App, { target: document.getElementById('app')! });
