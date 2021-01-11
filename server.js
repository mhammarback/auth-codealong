import express from 'express'
import bodyParser from 'body-parser'
import cors from 'cors'
import mongoose from 'mongoose'
import crypto from 'crypto'
import bcrypt from 'bcrypt-nodejs'


const mongoUrl = process.env.MONGO_URL || "mongodb://localhost/authCodealong"
mongoose.connect(mongoUrl, { useNewUrlParser: true, useUnifiedTopology: true })
mongoose.Promise = Promise

const User = mongoose.model('User', {
  name: {
    type: String,
    unique: true,
    required: true 
  },
  email: {
    type: String,
    unique: true,
    required: true
  },
  password: {
    type: String,
    required: true
  },
  accessToken: {
    type: String,
    default: () => crypto.randomBytes(128).toString('hex')
  }
})

const authenticteUser = async (req, res, next) => {
  const user = await User.findOne({accessToken: req.header('Authprization')})
  if(user){
    req.user = user
    next()
  }else {
    res.status(401).json({loggedOut:true})
  }
}

//   PORT=9000 npm start
const port = process.env.PORT || 8080
const app = express()

// Add middlewares to enable cors and json body parsing
app.use(cors())
app.use(bodyParser.json())

// Start defining your routes here
app.get('/', (req, res) => {
  res.send('Hello world')
})

app.post('/users', async (req,res) => {
  try{
    const {name, email, password} = req.body
    const user = new User({name, email, password: bcrypt.hashSync(password)})
    user.save()
    res.status(201).json({id: user._id, accessToken: user.accessToken})

  } catch(err) {
    res.status(400).json({message: 'Could not create user', errors:err.errors})
  }
})
app.get('/secrets', authenticteUser)
app.get('/secrets', (req, res) => {
  res.json({secret: ' this is a super secret message'})
})

app.post('/sessions', async (req,res) => {
  try { 
    const user = await User.findOne({email: req.body.email})
    if(user && bcrypt.compareSync(req.body.password, user.password)){
      res.json({userId: user._id, accessToken: user.accessToken})
  } else {
    res.json({notFound: true})
    }
  } catch(err) {
    res.status(404).json({ notFound: true})
  }
})

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`)
})
