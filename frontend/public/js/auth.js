// @ts-check
import { apiRequest } from './api.js';

const tabLogin = document.getElementById('tab-login');
const tabRegister = document.getElementById('tab-register');
const formLogin = document.getElementById('form-login');
const formRegister = document.getElementById('form-register');
const alertBox = document.getElementById('alert-box');

const registerPassword = document.getElementById('register-password');
const ruleLength = document.getElementById('rule-length');
const ruleUpper = document.getElementById('rule-upper');
const ruleLower = document.getElementById('rule-lower');
const ruleNumber = document.getElementById('rule-number');
const ruleSpecial = document.getElementById('rule-special');

// Pestañas
tabLogin?.addEventListener('click', () => {
  tabLogin.style.color = 'var(--accent-cyan)';
  tabRegister.style.color = 'var(--text-muted)';
  formLogin.style.display = 'block';
  formRegister.style.display = 'none';
  hideAlert();
});

tabRegister?.addEventListener('click', () => {
  tabRegister.style.color = 'var(--accent-cyan)';
  tabLogin.style.color = 'var(--text-muted)';
  formRegister.style.display = 'block';
  formLogin.style.display = 'none';
  hideAlert();
});

function showAlert(message, isError = true) {
  if (!alertBox) return;
  alertBox.textContent = message;
  alertBox.className = isError ? 'alert alert-error' : 'alert alert-success';
  alertBox.style.display = 'block';
}

function hideAlert() {
  if (alertBox) alertBox.style.display = 'none';
}

// Verificación visual de política de contraseña en tiempo real (RF-01)
registerPassword?.addEventListener('input', (e) => {
  // @ts-ignore
  const val = e.target.value;
  updateRule(ruleLength, val.length >= 12);
  updateRule(ruleUpper, /[A-Z]/.test(val));
  updateRule(ruleLower, /[a-z]/.test(val));
  updateRule(ruleNumber, /[0-9]/.test(val));
  updateRule(ruleSpecial, /[^A-Za-z0-9]/.test(val));
});

function updateRule(element, isValid) {
  if (!element) return;
  element.className = isValid ? 'valid' : 'invalid';
  element.textContent = (isValid ? '✅ ' : '⚪ ') + element.textContent.slice(2);
}

// Enviar Login (RF-02)
formLogin?.addEventListener('submit', async (e) => {
  e.preventDefault();
  hideAlert();

  // @ts-ignore
  const email = document.getElementById('login-email').value;
  // @ts-ignore
  const password = document.getElementById('login-password').value;

  try {
    const res = await apiRequest('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });

    // Guardar metadata no sensible de sesión en sessionStorage para la UI
    sessionStorage.setItem('vault_user', JSON.stringify(res.user));
    window.location.href = './index.html';
  } catch (error) {
    showAlert(error.message);
  }
});

// Enviar Registro (RF-01)
formRegister?.addEventListener('submit', async (e) => {
  e.preventDefault();
  hideAlert();

  // @ts-ignore
  const email = document.getElementById('register-email').value;
  // @ts-ignore
  const password = document.getElementById('register-password').value;

  try {
    await apiRequest('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });

    showAlert('¡Registro exitoso! Ya puedes iniciar sesión con tus credenciales.', false);
    formRegister.reset();
    tabLogin?.click();
  } catch (error) {
    showAlert(error.message);
  }
});

// Modal Forgot Password (RF-06)
const linkForgot = document.getElementById('link-forgot-password');
const modalForgot = document.getElementById('modal-forgot');
const btnCloseModal = document.getElementById('btn-close-modal');
const formForgot = document.getElementById('form-forgot');
const resetSection = document.getElementById('reset-section');
const formReset = document.getElementById('form-reset');
const modalAlert = document.getElementById('modal-alert');

linkForgot?.addEventListener('click', (e) => {
  e.preventDefault();
  if (modalForgot) modalForgot.style.display = 'flex';
});

btnCloseModal?.addEventListener('click', () => {
  if (modalForgot) modalForgot.style.display = 'none';
});

formForgot?.addEventListener('submit', async (e) => {
  e.preventDefault();
  // @ts-ignore
  const email = document.getElementById('forgot-email').value;

  try {
    const res = await apiRequest('/auth/forgot-password', {
      method: 'POST',
      body: JSON.stringify({ email }),
    });

    if (modalAlert) {
      modalAlert.textContent = res.message;
      modalAlert.className = 'alert alert-success';
      modalAlert.style.display = 'block';
    }

    if (res.debugToken) {
      // Auto-completar en entorno de prueba
      // @ts-ignore
      document.getElementById('reset-token').value = res.debugToken;
    }

    if (resetSection) resetSection.style.display = 'block';
  } catch (error) {
    if (modalAlert) {
      modalAlert.textContent = error.message;
      modalAlert.className = 'alert alert-error';
      modalAlert.style.display = 'block';
    }
  }
});

formReset?.addEventListener('submit', async (e) => {
  e.preventDefault();
  // @ts-ignore
  const token = document.getElementById('reset-token').value;
  // @ts-ignore
  const newPassword = document.getElementById('reset-password').value;

  try {
    const res = await apiRequest('/auth/reset-password', {
      method: 'POST',
      body: JSON.stringify({ token, newPassword }),
    });

    alert(res.message);
    if (modalForgot) modalForgot.style.display = 'none';
    formReset.reset();
  } catch (error) {
    alert('Error al restablecer: ' + error.message);
  }
});
