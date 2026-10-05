import express from 'express'
import cors from 'cors'
import pool from './config/db.js'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import auth from './middleware/auth.js'

const app = express()

app.use(cors())
app.use(express.json())

app.use((req, res, next) => {
  console.log(`${req.method} ${req.url}`)
  next()
})

app.get('/', (req, res) => {
  res.send('Servidor Soft Jobs funcionando')
})

app.get('/test-db', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM usuarios')
    res.json(result.rows)
  } catch (error) {
    console.error(error)
    res.status(500).json({ message: 'Error al consultar la base de datos' })
  }
})

app.post('/usuarios', async (req, res) => {
  try {
    const { email, password, rol, lenguage } = req.body

    const passwordHash = await bcrypt.hash(password, 10)

    const result = await pool.query(
        `INSERT INTO usuarios (email, password, rol, lenguage)
        VALUES ($1, $2, $3, $4)
        RETURNING id, email, rol, lenguage`,
        [email, passwordHash, rol, lenguage]
    )

    res.status(201).json(result.rows[0])
  } catch (error) {
    console.error(error)
    res.status(500).json({ message: 'Error al registrar usuario' })
  }
})

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body

    const result = await pool.query(
      'SELECT * FROM usuarios WHERE email = $1',
      [email]
    )

    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Credenciales incorrectas' })
    }

    const user = result.rows[0]

    const passwordValid = await bcrypt.compare(password, user.password)

    if (!passwordValid) {
      return res.status(401).json({ message: 'Credenciales incorrectas' })
    }

    const token = jwt.sign(
      { email: user.email },
      'clave_secreta_softjobs',
      { expiresIn: '1h' }
    )

    res.json({
      token
    })
  } catch (error) {
    console.error(error)
    res.status(500).json({ message: 'Error en el servidor' })
  }
})

app.get('/usuarios', auth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, email, rol, lenguage FROM usuarios WHERE email = $1',
      [req.user.email]
    )

    res.json(result.rows)
  } catch (error) {
    console.error(error)
    res.status(500).json({ message: 'Error al obtener usuario' })
  }
})

app.listen(3000, () => {
  console.log('Servidor ejecutándose en http://localhost:3000')
})
