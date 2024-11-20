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

const SECRET_KEY = process.env.SECRET_KEY || 'utesa-local';

const verifyRole = (requiredLevel) => {
  return (req, res, next) => {
    const { access_level } = req.user; 
    if (access_level < requiredLevel) {
      return res.status(403).json({ message: 'Acceso denegado: No tienes el nivel necesario' });
    }
    next();
  };
};

const authenticateTokenWithRole = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    console.log('Token no proporcionado');
    return res.status(401).json({ message: 'No autorizado. Token no proporcionado.' });
  }

  jwt.verify(token, SECRET_KEY, async (err, user) => {
    if (err) {
      console.log('Token inválido:', err); 
      return res.status(403).json({ message: 'No autorizado. Token inválido.' });
    }

    const [rows] = await db.query('SELECT * FROM admin_users WHERE id = ?', [user.id]);
    if (rows.length === 0) {
      console.log('Usuario no encontrado en la base de datos'); 
      return res.status(403).json({ message: 'No autorizado. Usuario no encontrado.' });
    }

    req.user = rows[0]; 
    next();
  });
};
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const [rows] = await db.query('SELECT * FROM admin_users WHERE username = ?', [username]);

    if (rows.length === 0) {
      return res.status(401).json({ message: 'Usuario o contraseña incorrecta.' });
    }

    const user = rows[0];

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Usuario o contraseña incorrecta.' });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username, access_level: user.access_level },
      SECRET_KEY,
      { expiresIn: '1h' }
    );

    res.json({ token });
  } catch (error) {
    console.error('Error en el inicio de sesión:', error);
    res.status(500).json({ message: 'Error en el servidor.' });
  }
});


app.get('/admin', authenticateTokenWithRole, verifyRole(3), (req, res) => {
  res.send('Bienvenido al Panel de Administración');
});

app.get('/docente', authenticateTokenWithRole, verifyRole(2), (req, res) => {
  res.send('Bienvenido al área de Docentes');
});

app.get('/projects', authenticateTokenWithRole, verifyRole(1), async (req, res) => {
  const userRole = req.user.access_level;
  console.log(`Usuario con nivel de acceso ${userRole} solicitando proyectos`);

  try {
    const [rows] = await db.query('SELECT * FROM projects');
    res.json(rows);
  } catch (error) {
    console.error('Error al obtener los proyectos:', error);
    res.status(500).json({ error: 'Error al obtener los proyectos' });
  }
});

app.post('/projects', authenticateTokenWithRole, verifyRole(3), async (req, res) => {
  const { title, author, career, year, fileUrl, summary } = req.body;

  console.log('Datos recibidos para crear proyecto:', req.body); 

  try {
    const [result] = await db.query(
      'INSERT INTO projects (title, author, career, year, fileUrl, summary) VALUES (?, ?, ?, ?, ?, ?)',
      [title, author, career, year, fileUrl, summary]
    );

    console.log('Proyecto creado con éxito:', result); 
    res.status(201).json({ message: 'Proyecto creado', projectId: result.insertId });
  } catch (error) {
    console.error('Error al crear el proyecto:', error);
    res.status(500).json({ error: 'Error al crear el proyecto.' });
  }
});


app.get('/projects/:id', authenticateTokenWithRole, verifyRole(2), async (req, res) => {
  const { id } = req.params;

  console.log(`Obteniendo proyecto con ID: ${id}`); 

  try {
    const [rows] = await db.query('SELECT * FROM projects WHERE id = ?', [id]);

    if (rows.length === 0) {
      console.log(`Proyecto con ID ${id} no encontrado`);
      return res.status(404).json({ message: 'Proyecto no encontrado' });
    }

    res.json(rows[0]); 
  } catch (error) {
    console.error(`Error al obtener el proyecto con ID ${id}:`, error);
    res.status(500).json({ error: 'Error al obtener el proyecto' });
  }
});

app.put('/projects/:id', authenticateTokenWithRole, verifyRole(3), async (req, res) => {
  const { id } = req.params;
  console.log(`ID recibido para actualizar: ${id}`); 
  console.log('Datos recibidos para actualizar:', req.body); 

  const { title, author, career, year, fileUrl, summary } = req.body;

  try {
    const [result] = await db.query(
      'UPDATE projects SET title = ?, author = ?, career = ?, year = ?, fileUrl = ?, summary = ? WHERE id = ?',
      [title, author, career, year, fileUrl, summary, id]
    );

    if (result.affectedRows === 0) {
      console.log(`Proyecto con ID ${id} no encontrado para actualizar`);
      return res.status(404).json({ message: 'Proyecto no encontrado' });
    }

    res.json({ message: 'Proyecto actualizado' });
  } catch (error) {
    console.error(`Error al actualizar el proyecto con ID ${id}:`, error);
    res.status(500).json({ error: 'Error al actualizar el proyecto' });
  }
});

app.delete('/projects/:id', authenticateTokenWithRole, verifyRole(3), async (req, res) => {
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

app.post('/searchProject', async (req, res) => {
  const { title, career, year, author } = req.body;

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

  if (author) {
    query += ' AND author LIKE ?';
    queryParams.push(`%${author}%`);
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

app.get('/careers', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM careers');
    res.json(rows);
  } catch (error) {
    console.error('Error al obtener las carreras:', error);
    res.status(500).json({ error: 'Error al obtener las carreras.' });
  }
});

app.post('/careers', authenticateTokenWithRole, verifyRole(3), async (req, res) => {
  const { name } = req.body;

  try {
    const [result] = await db.query('INSERT INTO careers (name) VALUES (?)', [name]);
    res.status(201).json({ message: 'Carrera añadida con éxito', careerId: result.insertId });
  } catch (error) {
    console.error('Error al añadir la carrera:', error);
    res.status(500).json({ error: 'Error al añadir la carrera.' });
  }
});

app.delete('/careers/:id', authenticateTokenWithRole, verifyRole(3), async (req, res) => {
  const { id } = req.params;

  try {
    const [result] = await db.query('DELETE FROM careers WHERE id = ?', [id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Carrera no encontrada.' });
    }
    res.json({ message: 'Carrera eliminada con éxito.' });
  } catch (error) {
    console.error('Error al eliminar la carrera:', error);
    res.status(500).json({ error: 'Error al eliminar la carrera.' });
  }
});

app.post('/admin_users', authenticateTokenWithRole, verifyRole(3), async (req, res) => {
  const { username, password, access_level } = req.body;

  if (!username || !password || !access_level) {
    return res.status(400).json({ message: 'Todos los campos son obligatorios.' });
  }

  try {
    const [existingUser] = await db.query('SELECT * FROM admin_users WHERE username = ?', [username]);
    if (existingUser.length > 0) {
      return res.status(409).json({ message: 'El nombre de usuario ya existe.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const [result] = await db.query(
      'INSERT INTO admin_users (username, password, access_level) VALUES (?, ?, ?)',
      [username, hashedPassword, access_level]
    );

    res.status(201).json({
      message: 'Usuario creado exitosamente.',
      userId: result.insertId,
    });
  } catch (error) {
    console.error('Error al añadir usuario:', error);
    res.status(500).json({ message: 'Error al añadir usuario.' });
  }
});

app.get('/health', (req, res) => {
  res.status(200).json({ message: 'Ok' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor escuchando en el puerto ${PORT}`);
});
