// @ts-check
import { apiRequest } from './api.js';

const userDisplay = document.getElementById('user-display');
const roleBadge = document.getElementById('role-badge');
const linkAdmin = document.getElementById('link-admin');
const btnLogout = document.getElementById('btn-logout');
const notesTableBody = document.getElementById('notes-table-body');
const alertBox = document.getElementById('alert-box');

const modalNote = document.getElementById('modal-note');
const btnNewNote = document.getElementById('btn-new-note');
const btnCloseNoteModal = document.getElementById('btn-close-note-modal');
const btnCancelNote = document.getElementById('btn-cancel-note');
const formNote = document.getElementById('form-note');

// Verificar sesión
const cachedUser = JSON.parse(sessionStorage.getItem('vault_user') || 'null');
if (!cachedUser) {
  window.location.href = '/login.html';
} else {
  if (userDisplay) userDisplay.textContent = cachedUser.email;
  if (roleBadge) {
    roleBadge.textContent = cachedUser.role;
    roleBadge.className = cachedUser.role === 'ADMIN' ? 'badge-admin' : 'badge-user';
  }
  if (cachedUser.role === 'ADMIN' && linkAdmin) {
    linkAdmin.style.display = 'inline-block';
  }
}

// Cerrar sesión
btnLogout?.addEventListener('click', async () => {
  try {
    await apiRequest('/auth/logout', { method: 'POST' });
  } catch {}
  sessionStorage.removeItem('vault_user');
  window.location.href = '/login.html';
});

// Cargar notas (RF-04, RF-05)
async function loadNotes() {
  try {
    const res = await apiRequest('/notes');
    renderNotes(res.notes);
  } catch (error) {
    if (alertBox) {
      alertBox.textContent = 'Error al cargar notas: ' + error.message;
      alertBox.className = 'alert alert-error';
      alertBox.style.display = 'block';
    }
  }
}

function renderNotes(notes) {
  if (!notesTableBody) return;
  if (notes.length === 0) {
    notesTableBody.innerHTML = `
      <tr>
        <td colspan="4" style="text-align: center; color: var(--text-muted);">
          No tienes notas registradas en tu bóveda. Haz clic en "+ Nueva Nota Cifrada".
        </td>
      </tr>
    `;
    return;
  }

  notesTableBody.innerHTML = notes.map((note) => `
    <tr>
      <td><strong>${escapeHtml(note.title)}</strong></td>
      <td><span class="sensitive-masked">${escapeHtml(note.sensitiveFieldMasked)}</span></td>
      <td style="color: var(--text-muted); font-size: 0.8rem;">${new Date(note.createdAt).toLocaleString()}</td>
      <td>
        <button class="btn btn-outline btn-view" data-id="${note.id}" style="padding: 0.25rem 0.6rem; font-size: 0.8rem;">Descifrar</button>
        <button class="btn btn-danger btn-delete" data-id="${note.id}" style="padding: 0.25rem 0.6rem; font-size: 0.8rem;">Eliminar</button>
      </td>
    </tr>
  `).join('');

  // Event listeners para descifrar y eliminar
  document.querySelectorAll('.btn-view').forEach((btn) => {
    btn.addEventListener('click', async () => {
      // @ts-ignore
      const noteId = btn.dataset.id;
      await viewDecryptedNote(noteId);
    });
  });

  document.querySelectorAll('.btn-delete').forEach((btn) => {
    btn.addEventListener('click', async () => {
      // @ts-ignore
      const noteId = btn.dataset.id;
      if (confirm('¿Estás seguro de eliminar esta nota privada de la bóveda?')) {
        await deleteNote(noteId);
      }
    });
  });
}

async function viewDecryptedNote(noteId) {
  try {
    const res = await apiRequest(`/notes/${noteId}`);
    const note = res.note;

    // Mostrar modal con los datos descifrados en AES-256-GCM
    // @ts-ignore
    document.getElementById('modal-note-title').textContent = 'Nota Descifrada: ' + note.title;
    // @ts-ignore
    document.getElementById('input-note-title').value = note.title;
    // @ts-ignore
    document.getElementById('input-sensitive-field').value = note.sensitiveField;
    // @ts-ignore
    document.getElementById('input-note-content').value = note.content;
    // @ts-ignore
    document.getElementById('note-id').value = note.id;

    if (modalNote) modalNote.style.display = 'flex';
  } catch (error) {
    alert('Fallo de acceso o descifrado: ' + error.message);
  }
}

async function deleteNote(noteId) {
  try {
    await apiRequest(`/notes/${noteId}`, { method: 'DELETE' });
    await loadNotes();
  } catch (error) {
    alert('Error al eliminar: ' + error.message);
  }
}

// Modal handling
btnNewNote?.addEventListener('click', () => {
  formNote?.reset();
  // @ts-ignore
  document.getElementById('note-id').value = '';
  // @ts-ignore
  document.getElementById('modal-note-title').textContent = 'Nueva Nota Cifrada';
  if (modalNote) modalNote.style.display = 'flex';
});

btnCloseNoteModal?.addEventListener('click', () => {
  if (modalNote) modalNote.style.display = 'none';
});

btnCancelNote?.addEventListener('click', () => {
  if (modalNote) modalNote.style.display = 'none';
});

formNote?.addEventListener('submit', async (e) => {
  e.preventDefault();
  // @ts-ignore
  const noteId = document.getElementById('note-id').value;
  // @ts-ignore
  const title = document.getElementById('input-note-title').value;
  // @ts-ignore
  const sensitiveField = document.getElementById('input-sensitive-field').value;
  // @ts-ignore
  const content = document.getElementById('input-note-content').value;

  try {
    if (noteId) {
      await apiRequest(`/notes/${noteId}`, {
        method: 'PUT',
        body: JSON.stringify({ title, sensitiveField, content }),
      });
    } else {
      await apiRequest('/notes', {
        method: 'POST',
        body: JSON.stringify({ title, sensitiveField, content }),
      });
    }

    if (modalNote) modalNote.style.display = 'none';
    await loadNotes();
  } catch (error) {
    alert('Error al guardar nota: ' + error.message);
  }
});

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

loadNotes();
