// @ts-check
/**
 * Cliente HTTP unificado para SecureVault
 * Implementa comunicación segura con la API mediante cookies HttpOnly (credentials: 'include')
 */

const API_BASE_URL = '/api/v1';

export async function apiRequest(endpoint, options = {}) {
  const url = `${API_BASE_URL}${endpoint}`;
  
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {}),
  };

  const config = {
    ...options,
    headers,
    credentials: 'include', // Mandatorio para enviar y recibir cookies HttpOnly SameSite=Strict
  };

  try {
    const response = await fetch(url, config);
    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      const errorMsg = data.error || (data.details && data.details.join(', ')) || `Error ${response.status}`;
      const error = new Error(errorMsg);
      // @ts-ignore
      error.status = response.status;
      // @ts-ignore
      error.data = data;
      throw error;
    }

    return data;
  } catch (error) {
    if (error.status === 401 && !window.location.pathname.includes('login.html')) {
      // Redirigir a login si la sesión ha expirado
      window.location.href = '/login.html?expired=true';
    }
    throw error;
  }
}
