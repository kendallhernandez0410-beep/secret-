// @ts-check
import { Router } from 'express';
import {
  createNoteSchema,
  updateNoteSchema,
  createNote,
  listUserNotes,
  getNoteById,
  updateNote,
  deleteNote,
} from '../services/note.service.js';
import { authenticateUser } from '../middlewares/auth.middleware.js';

const router = Router();

// Todas las rutas de notas requieren autenticación obligatoria
router.use(authenticateUser);

/**
 * RF-04, RF-05: Listar notas del usuario autenticado (datos sensibles enmascarados)
 */
router.get('/', async (req, res, next) => {
  try {
    const notes = await listUserNotes(req.user.id);
    res.json({ notes });
  } catch (error) {
    next(error);
  }
});

/**
 * RF-04, RF-05: Crear nueva nota privada cifrada con AES-256-GCM
 */
router.post('/', async (req, res, next) => {
  try {
    const validated = createNoteSchema.safeParse(req.body);
    if (!validated.success) {
      const issues = validated.error.issues || validated.error.errors || [];
      return res.status(400).json({
        error: 'Datos de la nota inválidos.',
        details: issues.map((e) => e.message),
      });
    }

    const note = await createNote(
      {
        userId: req.user.id,
        title: validated.data.title,
        content: validated.data.content,
        sensitiveField: validated.data.sensitiveField,
      },
      req.ip,
      req.headers['user-agent']
    );

    res.status(201).json({
      message: 'Nota cifrada y creada exitosamente.',
      note,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * RF-04, RF-05: Obtener y descifrar nota específica (Control de tenencia / Anti-IDOR)
 */
router.get('/:id', async (req, res, next) => {
  try {
    const noteId = req.params.id;
    const isAdmin = req.user.role === 'ADMIN';

    const note = await getNoteById(noteId, req.user.id, isAdmin, req.ip, req.headers['user-agent']);
    res.json({ note });
  } catch (error) {
    next(error);
  }
});

/**
 * RF-04, RF-05: Actualizar nota privada (Re-cifrado con nuevo IV y Anti-IDOR)
 */
router.put('/:id', async (req, res, next) => {
  try {
    const noteId = req.params.id;
    const validated = updateNoteSchema.safeParse(req.body);
    if (!validated.success) {
      const issues = validated.error.issues || validated.error.errors || [];
      return res.status(400).json({
        error: 'Datos de actualización inválidos.',
        details: issues.map((e) => e.message),
      });
    }

    const updated = await updateNote(
      {
        noteId,
        userId: req.user.id,
        ...validated.data,
      },
      req.ip,
      req.headers['user-agent']
    );

    res.json({
      message: 'Nota actualizada exitosamente.',
      note: updated,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * RF-04: Eliminar nota privada (Anti-IDOR)
 */
router.delete('/:id', async (req, res, next) => {
  try {
    const noteId = req.params.id;
    const result = await deleteNote(noteId, req.user.id, req.ip, req.headers['user-agent']);
    res.json(result);
  } catch (error) {
    next(error);
  }
});

export default router;
