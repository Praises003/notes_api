const express = require('express');
const router = express.Router();
const { createNote, getNotes, deleteNote, getAllNotes } = require('../controllers/notesController');
const {verifyToken, verifyAdmin} = require('../middleware/authMiddleware');

router.post('/notes', verifyToken, createNote);
router.get('/notes', verifyToken, getNotes);

router.get('/all-notes', verifyToken, verifyAdmin, getAllNotes);
router.delete('/notes/:id', verifyToken, deleteNote);

module.exports = router;
