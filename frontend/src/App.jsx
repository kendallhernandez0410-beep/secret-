import React, { useState, useEffect } from 'react';

// URL del backend: en desarrollo o local usa localhost:3000, o configurable
const API_URL = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1' 
  ? 'http://127.0.0.1:3000/api/v1' 
  : '/api/v1';

export default function App() {
  const [user, setUser] = useState(() => {
    try {
      return JSON.parse(sessionStorage.getItem('vault_user') || 'null');
    } catch {
      return null;
    }
  });

  const [currentView, setCurrentView] = useState('vault'); // 'vault' | 'admin'

  const handleLogin = (userData) => {
    setUser(userData);
    sessionStorage.setItem('vault_user', JSON.stringify(userData));
    setCurrentView('vault');
  };

  const handleLogout = async () => {
    try {
      await fetch(`${API_URL}/auth/logout`, { method: 'POST', credentials: 'include' });
    } catch {}
    setUser(null);
    sessionStorage.removeItem('vault_user');
  };

  return (
    <div>
      <header>
        <div className="logo">
          <span>🛡️</span> SecureVault <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontWeight: 'normal' }}>| React App</span>
        </div>
        {user && (
          <nav>
            <span style={{ fontSize: '0.9rem', color: 'var(--text-main)' }}>{user.email}</span>
            <span className={user.role === 'ADMIN' ? 'badge-admin' : 'badge-user'}>{user.role}</span>
            {user.role === 'ADMIN' && (
              <button 
                className="btn btn-outline" 
                style={{ padding: '0.3rem 0.8rem', fontSize: '0.85rem' }}
                onClick={() => setCurrentView(currentView === 'admin' ? 'vault' : 'admin')}
              >
                {currentView === 'admin' ? 'Ver Bóveda' : 'Panel Admin'}
              </button>
            )}
            <button className="btn btn-outline" style={{ padding: '0.3rem 0.8rem', fontSize: '0.85rem' }} onClick={handleLogout}>
              Cerrar Sesión
            </button>
          </nav>
        )}
      </header>

      <main>
        {!user ? (
          <AuthView onLogin={handleLogin} />
        ) : currentView === 'admin' && user.role === 'ADMIN' ? (
          <AdminView />
        ) : (
          <VaultView user={user} />
        )}
      </main>
    </div>
  );
}

// -----------------------------------------------------------------------------
// Vista de Autenticación (Login, Registro con Política y Reset de Contraseña)
// -----------------------------------------------------------------------------
function AuthView({ onLogin }) {
  const [tab, setTab] = useState('login'); // 'login' | 'register'
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [alert, setAlert] = useState(null);
  const [showForgot, setShowForgot] = useState(false);

  // Validación de política de contraseñas en tiempo real (RF-01)
  const policy = {
    length: password.length >= 12,
    upper: /[A-Z]/.test(password),
    lower: /[a-z]/.test(password),
    number: /[0-9]/.test(password),
    special: /[^A-Za-z0-9]/.test(password),
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setAlert(null);

    const endpoint = tab === 'login' ? '/auth/login' : '/auth/register';

    try {
      const res = await fetch(`${API_URL}${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ email, password }),
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || (data.details && data.details.join(', ')) || 'Error en la solicitud');
      }

      if (tab === 'login') {
        onLogin(data.user);
      } else {
        setAlert({ type: 'success', msg: '¡Usuario registrado exitosamente! Inicia sesión con tus credenciales.' });
        setTab('login');
      }
    } catch (err) {
      setAlert({ type: 'error', msg: err.message });
    }
  };

  return (
    <div className="card" style={{ maxWidth: '480px', margin: '2rem auto' }}>
      <div style={{ display: 'flex', gap: '1rem', borderBottom: '1px solid var(--border-color)', marginBottom: '1.5rem', paddingBottom: '0.5rem' }}>
        <button 
          className="btn btn-outline" 
          style={{ flex: 1, border: 'none', fontWeight: tab === 'login' ? 'bold' : 'normal', color: tab === 'login' ? 'var(--accent-cyan)' : 'var(--text-muted)' }}
          onClick={() => { setTab('login'); setAlert(null); }}
        >
          Iniciar Sesión
        </button>
        <button 
          className="btn btn-outline" 
          style={{ flex: 1, border: 'none', fontWeight: tab === 'register' ? 'bold' : 'normal', color: tab === 'register' ? 'var(--accent-cyan)' : 'var(--text-muted)' }}
          onClick={() => { setTab('register'); setAlert(null); }}
        >
          Registrarse
        </button>
      </div>

      {alert && <div className={`alert alert-${alert.type}`}>{alert.msg}</div>}

      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label>Correo Electrónico</label>
          <input type="email" required value={email} onChange={(e) => setEmail(e.target.value)} placeholder="usuario@vault.local" />
        </div>

        <div className="form-group">
          <label>{tab === 'login' ? 'Contraseña' : 'Contraseña Maestra (Mínimo 12 caracteres)'}</label>
          <input type="password" required value={password} onChange={(e) => setPassword(e.target.value)} placeholder="••••••••••••" />
          
          {tab === 'register' && (
            <ul className="policy-list">
              <li className={policy.length ? 'valid' : 'invalid'}>{policy.length ? '✅' : '⚪'} Mínimo 12 caracteres</li>
              <li className={policy.upper ? 'valid' : 'invalid'}>{policy.upper ? '✅' : '⚪'} Al menos una mayúscula</li>
              <li className={policy.lower ? 'valid' : 'invalid'}>{policy.lower ? '✅' : '⚪'} Al menos una minúscula</li>
              <li className={policy.number ? 'valid' : 'invalid'}>{policy.number ? '✅' : '⚪'} Al menos un número</li>
              <li className={policy.special ? 'valid' : 'invalid'}>{policy.special ? '✅' : '⚪'} Al menos un símbolo (@$!%*?&#)</li>
            </ul>
          )}
        </div>

        <button type="submit" className="btn btn-primary" style={{ width: '100%', marginTop: '0.5rem' }}>
          {tab === 'login' ? 'Ingresar a la Bóveda' : 'Crear Cuenta Segura'}
        </button>

        {tab === 'login' && (
          <div style={{ textAlign: 'center', marginTop: '1rem' }}>
            <a href="#" style={{ fontSize: '0.85rem', color: 'var(--text-muted)', textDecoration: 'none' }} onClick={(e) => { e.preventDefault(); setShowForgot(true); }}>
              ¿Olvidaste tu contraseña?
            </a>
          </div>
        )}
      </form>

      {showForgot && <ForgotPasswordModal onClose={() => setShowForgot(false)} />}
    </div>
  );
}

// -----------------------------------------------------------------------------
// Vista de la Bóveda de Notas Privadas Cifradas (RF-04 & RF-05)
// -----------------------------------------------------------------------------
function VaultView({ user }) {
  const [notes, setNotes] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [selectedNote, setSelectedNote] = useState(null);
  const [title, setTitle] = useState('');
  const [sensitiveField, setSensitiveField] = useState('');
  const [content, setContent] = useState('');

  const loadNotes = async () => {
    try {
      const res = await fetch(`${API_URL}/notes`, { credentials: 'include' });
      const data = await res.json();
      if (res.ok) setNotes(data.notes || []);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadNotes();
  }, []);

  const handleSave = async (e) => {
    e.preventDefault();
    try {
      const endpoint = selectedNote?.id ? `${API_URL}/notes/${selectedNote.id}` : `${API_URL}/notes`;
      const method = selectedNote?.id ? 'PUT' : 'POST';

      const res = await fetch(endpoint, {
        method,
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ title, sensitiveField, content }),
      });

      if (res.ok) {
        setShowModal(false);
        loadNotes();
      } else {
        const err = await res.json();
        alert('Error: ' + err.error);
      }
    } catch (err) {
      alert('Error al guardar: ' + err.message);
    }
  };

  const handleDecrypt = async (noteId) => {
    try {
      const res = await fetch(`${API_URL}/notes/${noteId}`, { credentials: 'include' });
      const data = await res.json();
      if (res.ok) {
        setSelectedNote(data.note);
        setTitle(data.note.title);
        setSensitiveField(data.note.sensitiveField);
        setContent(data.note.content);
        setShowModal(true);
      } else {
        alert('Acceso no autorizado o fallo de descifrado');
      }
    } catch (err) {
      alert(err.message);
    }
  };

  const handleDelete = async (noteId) => {
    if (!confirm('¿Seguro de eliminar esta nota privada de la bóveda?')) return;
    try {
      const res = await fetch(`${API_URL}/notes/${noteId}`, { method: 'DELETE', credentials: 'include' });
      if (res.ok) loadNotes();
    } catch (err) {
      alert(err.message);
    }
  };

  return (
    <div className="card">
      <div className="card-title">
        <span>Bóveda de Notas Privadas (AES-256-GCM)</span>
        <button 
          className="btn btn-primary" 
          onClick={() => {
            setSelectedNote(null);
            setTitle('');
            setSensitiveField('');
            setContent('');
            setShowModal(true);
          }}
        >
          + Nueva Nota Cifrada
        </button>
      </div>

      <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem', marginBottom: '1.5rem' }}>
        Notas cifradas en reposo con <strong>AES-256-GCM</strong> (IV aleatorio de 12B + AuthTag de 16B). Campos sensibles enmascarados para evitar fugas.
      </p>

      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th>Título</th>
              <th>Dato Confidencial (Enmascarado)</th>
              <th>Fecha Creación</th>
              <th>Acciones</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan="4" style={{ textAlign: 'center', color: 'var(--text-muted)' }}>Cargando notas...</td></tr>
            ) : notes.length === 0 ? (
              <tr><td colSpan="4" style={{ textAlign: 'center', color: 'var(--text-muted)' }}>No tienes notas registradas. Haz clic en "+ Nueva Nota Cifrada".</td></tr>
            ) : (
              notes.map((n) => (
                <tr key={n.id}>
                  <td><strong>{n.title}</strong></td>
                  <td><span className="sensitive-masked">{n.sensitiveFieldMasked}</span></td>
                  <td style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>{new Date(n.createdAt).toLocaleString()}</td>
                  <td>
                    <button className="btn btn-outline" style={{ padding: '0.25rem 0.6rem', fontSize: '0.8rem', marginRight: '0.5rem' }} onClick={() => handleDecrypt(n.id)}>
                      Descifrar
                    </button>
                    <button className="btn btn-danger" style={{ padding: '0.25rem 0.6rem', fontSize: '0.8rem' }} onClick={() => handleDelete(n.id)}>
                      Eliminar
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {showModal && (
        <div className="modal-overlay">
          <div className="modal-content">
            <button className="modal-close" onClick={() => setShowModal(false)}>&times;</button>
            <h3 style={{ marginBottom: '1.5rem' }}>{selectedNote ? 'Nota Descifrada' : 'Nueva Nota Cifrada'}</h3>
            <form onSubmit={handleSave}>
              <div className="form-group">
                <label>Título</label>
                <input type="text" required value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Ej: Credenciales Base de Datos" />
              </div>
              <div className="form-group">
                <label>Campo Sensible a Enmascarar (RF-05)</label>
                <input type="text" required value={sensitiveField} onChange={(e) => setSensitiveField(e.target.value)} placeholder="Ej: 4111-2222-3333-4444" />
                <small style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>Se mostrará como ********-4444 en listados públicos.</small>
              </div>
              <div className="form-group">
                <label>Contenido Privado (Cifrado AES-256-GCM)</label>
                <textarea rows="4" required value={content} onChange={(e) => setContent(e.target.value)} placeholder="Contenido confidencial..." />
              </div>
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '1.5rem' }}>
                <button type="button" className="btn btn-outline" onClick={() => setShowModal(false)}>Cancelar</button>
                <button type="submit" className="btn btn-primary">Cifrar y Guardar</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

// -----------------------------------------------------------------------------
// Vista de Administración (Usuarios y Bitácora de Auditoría RF-07 / OWASP A09)
// -----------------------------------------------------------------------------
function AdminView() {
  const [users, setUsers] = useState([]);
  const [logs, setLogs] = useState([]);

  useEffect(() => {
    fetch(`${API_URL}/admin/users`, { credentials: 'include' }).then(r => r.json()).then(d => setUsers(d.users || []));
    fetch(`${API_URL}/admin/audit-logs?limit=50`, { credentials: 'include' }).then(r => r.json()).then(d => setLogs(d.logs || []));
  }, []);

  return (
    <div>
      <div className="card" style={{ marginBottom: '2rem' }}>
        <div className="card-title"><span>Usuarios Registrados en Base de Datos (RF-07)</span></div>
        <div className="table-container">
          <table>
            <thead>
              <tr><th>ID</th><th>Email</th><th>Rol</th><th>Fecha Registro</th></tr>
            </thead>
            <tbody>
              {users.map(u => (
                <tr key={u.id}>
                  <td style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>{u.id}</td>
                  <td>{u.email}</td>
                  <td><span className={u.role === 'ADMIN' ? 'badge-admin' : 'badge-user'}>{u.role}</span></td>
                  <td style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>{new Date(u.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="card">
        <div className="card-title"><span>Bitácora de Auditoría Inmutable (OWASP A09)</span></div>
        <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', marginBottom: '1.5rem' }}>
          Toda contraseña o token es redactado automáticamente como <code>[REDACTED_BY_AUDIT_POLICY]</code>.
        </p>
        <div className="table-container">
          <table>
            <thead>
              <tr><th>Timestamp</th><th>Evento</th><th>IP Origen</th><th>Detalles Sanitizados</th></tr>
            </thead>
            <tbody>
              {logs.map(l => (
                <tr key={l.id}>
                  <td style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>{new Date(l.created_at).toLocaleString()}</td>
                  <td><strong style={{ color: l.event_type.includes('FAIL') || l.event_type.includes('DENIED') ? 'var(--accent-rose)' : 'var(--accent-emerald)', fontSize: '0.8rem' }}>{l.event_type}</strong></td>
                  <td style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>{l.ip_address}</td>
                  <td style={{ fontFamily: 'monospace', fontSize: '0.75rem', maxWidth: '300px', wordBreak: 'break-all' }}>{l.details}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// -----------------------------------------------------------------------------
// Modal de Recuperación de Contraseña (RF-06)
// -----------------------------------------------------------------------------
function ForgotPasswordModal({ onClose }) {
  const [email, setEmail] = useState('');
  const [token, setToken] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [msg, setMsg] = useState(null);
  const [showReset, setShowReset] = useState(false);

  const handleRequest = async (e) => {
    e.preventDefault();
    const res = await fetch(`${API_URL}/auth/forgot-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email })
    });
    const d = await res.json();
    setMsg(d.message);
    if (d.debugToken) setToken(d.debugToken);
    setShowReset(true);
  };

  const handleReset = async (e) => {
    e.preventDefault();
    const res = await fetch(`${API_URL}/auth/reset-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token, newPassword })
    });
    const d = await res.json();
    if (res.ok) {
      alert(d.message);
      onClose();
    } else {
      alert('Error: ' + d.error);
    }
  };

  return (
    <div className="modal-overlay">
      <div className="modal-content">
        <button className="modal-close" onClick={onClose}>&times;</button>
        <h3 style={{ marginBottom: '1rem' }}>Recuperación de Contraseña (RF-06)</h3>
        {msg && <div className="alert alert-success">{msg}</div>}
        <form onSubmit={handleRequest}>
          <div className="form-group">
            <label>Correo Electrónico</label>
            <input type="email" required value={email} onChange={e => setEmail(e.target.value)} placeholder="tu-email@vault.local" />
          </div>
          <button type="submit" className="btn btn-primary" style={{ width: '100%' }}>Generar Enlace Seguro</button>
        </form>

        {showReset && (
          <form onSubmit={handleReset} style={{ marginTop: '1.5rem', borderTop: '1px solid var(--border-color)', paddingTop: '1.5rem' }}>
            <div className="form-group">
              <label>Token SHA-256 (32 Bytes CSPRNG)</label>
              <input type="text" required value={token} onChange={e => setToken(e.target.value)} />
            </div>
            <div className="form-group">
              <label>Nueva Contraseña Robusta</label>
              <input type="password" required value={newPassword} onChange={e => setNewPassword(e.target.value)} placeholder="••••••••••••" />
            </div>
            <button type="submit" className="btn btn-primary" style={{ width: '100%' }}>Restablecer Contraseña</button>
          </form>
        )}
      </div>
    </div>
  );
}
