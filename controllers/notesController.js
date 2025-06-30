const Note = require('../models/Note');
const { z } = require('zod');

// Zod Validation Schema for Note
const noteSchema = z.object({
    title: z.string().min(3, 'Title should be at least 3 characters'),
    content: z.string().min(10, 'Content should be at least 10 characters')
});

// Create a new note
exports.createNote = async (req, res) => {
    try {
        const data = noteSchema.parse(req.body);  // Input validation using Zod

        const newNote = new Note({
            title: data.title,
            content: data.content,
            user: req.user.userId // Attach logged-in user ID
        });

        await newNote.save();
        res.status(201).json(newNote);
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
};

exports.getAllNotes = async (req, res) => {
    try {
        const notes = await Note.find().populate('user', 'name email'); // Populate user details
        res.status(200).json(notes);
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
}

// Fetch all notes for the logged-in user
exports.getNotes = async (req, res) => {
    try {
        const notes = await Note.find({ user: req.user.userId });
        res.status(200).json(notes);
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
};

// Delete a specific note by ID
exports.deleteNote = async (req, res) => {
    try {
        const note = await Note.findById(req.params.id);
        if (!note || note.user.toString() !== req.user.userId) {
            return res.status(404).json({ message: 'Note not found or unauthorized' });
        }

        await note.remove();
        res.status(200).json({ message: 'Note deleted successfully' });
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
};
