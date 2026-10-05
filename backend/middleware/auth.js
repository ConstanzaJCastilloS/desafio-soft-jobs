import jwt from 'jsonwebtoken'

const SECRET_KEY = 'clave_secreta_softjobs'

const auth = (req, res, next) => {
  const authHeader = req.headers.authorization

  if (!authHeader) {
    return res.status(401).json({ message: 'Token requerido' })
  }

  const token = authHeader.split(' ')[1]

  if (!token) {
    return res.status(401).json({ message: 'Token requerido' })
  }

  try {
    const decoded = jwt.verify(token, SECRET_KEY)

    req.user = decoded

    next()
  } catch (error) {
    return res.status(401).json({ message: 'Token inválido' })
  }
}

export default auth
