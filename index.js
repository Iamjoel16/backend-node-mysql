require('dotenv').config();
const express = require('express');
const db = require('./db/connections');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { authenticateToken } = require('./middlewares/auth');

const app = express();
app.use(express.json());
app.use(cors());
app.use('/pdfs', express.static('pdfs'));

const SECRET_KEY = process.env.SECRET_KEY || 'utesa_local';

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  let data;

  try {
    await db.query('SELECT * FROM admin_users WHERE username = ?', [username]).then((res) => data = res);
  } catch (e) {
    res.json({ message: 'cannot find' })
  }

  const { id: idDb, username: userDb, password: passDb } = data[0][0] || []

  let id = idDb ?? 1

  if (password === passDb) {
    const token = jwt.sign({ id, username: userDb }, SECRET_KEY, { expiresIn: '1h' });
    return res.json({ token });
  } else {
    return res.status(401).json({ message: 'Usuario o contraseña incorrecta' });
  }
});

app.get('/admin', authenticateToken, (req, res) => {
  res.send('Bienvenido al Panel de Administración');
});

app.post('/logout', (req, res) => {
  return res.json({ message: 'Sesión cerrada correctamente' });
});

app.post('/projects', async (req, res) => {
  const { title, author, career, year, fileUrl, summary } = req.body;

  try {
    const [result] = await db.query('INSERT INTO projects (title, author, career, year, fileUrl, summary) VALUES (?, ?, ?, ?, ?, ?)', [title, author, career, year, fileUrl, summary]);

    console.log(result);

    res.status(201).json({ message: 'Proyecto creado', projectId: result.insertId });
  } catch (error) {
    res.status(500).json({ error: error });
  }
});

app.get('/projects', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM projects');
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener los proyectos' });
  }
});

app.get('/projects/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const [rows] = await db.query('SELECT * FROM projects WHERE id = ?', [id]);
    if (rows.length === 0) {
      return res.status(404).json({ message: 'Proyecto no encontrado' });
    }
    res.json(rows[0]);
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener el proyecto' });
  }
});

app.post('/searchProject', async (req, res) => {
  const { title, career, year } = req.body;

  let query = 'SELECT * FROM projects WHERE 1=1';
  const queryParams = [];

  if (title) {
    query += ' AND title LIKE ?';
    queryParams.push(`%${title}%`);
  }

  if (career) {
    query += ' AND career = ?';
    queryParams.push(career);
  }

  if (year) {
    query += ' AND year = ?';
    queryParams.push(year);
  }

  try {
    const [rows] = await db.query(query, queryParams);

    if (rows.length === 0) {
      return res.status(404).json({ message: 'No se encontraron proyectos con los criterios especificados' });
    }

    res.json(rows);
  } catch (error) {
    console.error('Error al buscar los proyectos:', error);
    res.status(500).json({ error: 'Error al buscar los proyectos' });
  }
});

app.put('/projects/:id', async (req, res) => {
  const { id } = req.params;
  const { title, author, career, year, fileUrl, summary } = req.body;

  try {
    const [result] = await db.query('UPDATE projects SET title = ?, author = ?, career = ?, year = ?, fileUrl = ?, summary = ? WHERE id = ?',
      [title, author, career, year, fileUrl, summary, id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Proyecto no encontrado' });
    }
    res.json({ message: 'Proyecto actualizado' });
  } catch (error) {
    res.status(500).json({ error: 'Error al actualizar el proyecto' });
  }
});

app.delete('/projects/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const [result] = await db.query('DELETE FROM projects WHERE id = ?', [id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Proyecto no encontrado' });
    }
    res.json({ message: 'Proyecto eliminado' });
  } catch (error) {
    res.status(500).json({ error: 'Error al eliminar el proyecto' });
  }
});

app.get('/health', (req, res) => {
  res.status(200);
  res.json({ message: 'Ok' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor escuchando en el puerto ${PORT}`);
});
