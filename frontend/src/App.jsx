/**
 * App.jsx — LogLens Root
 */
import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom';
import UploadPage from './components/UploadPage.jsx';
import Dashboard  from './components/Dashboard.jsx';
import './App.css';

function Navbar() {
  return (
    <nav className="navbar">
      <NavLink to="/" className="nav-brand">
        <span className="brand-icon">🔍</span>
        <span className="brand-text">LogLens</span>
        <span className="brand-tag">SIEM-lite</span>
      </NavLink>
      <div className="nav-links">
        <NavLink to="/" className={({isActive}) => isActive ? 'nav-link active' : 'nav-link'}>Analyse</NavLink>
      </div>
    </nav>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <div className="app">
        <Navbar />
        <main className="main-content">
          <Routes>
            <Route path="/"              element={<UploadPage />} />
            <Route path="/report/:jobId" element={<Dashboard />}  />
          </Routes>
        </main>
        <footer className="footer">LogLens · Apache/Nginx CLF Parser · Regex Threat Detection · Behavioral Analysis</footer>
      </div>
    </BrowserRouter>
  );
}
