import { createRoot } from 'react-dom/client';
import { App } from './App';
import { Overlays } from './ui';
import './styles.css';

createRoot(document.getElementById('root')!).render(<><App /><Overlays /></>);
