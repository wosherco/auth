# Server-Side Registration and Authentication

This guide explains how to implement a server that registers users and teams from @localfirst/auth, provides authenticated access to services, and enables features like encrypted backups and signaling — all while preventing spam and maintaining the security model.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Registration Flow](#registration-flow)
- [Authentication Flow](#authentication-flow)
- [Implementation](#implementation)
- [Spam Prevention](#spam-prevention)
- [Use Cases](#use-cases)
- [Security Considerations](#security-considerations)
- [Complete Example](#complete-example)

## Overview

@localfirst/auth is designed to be decentralized and local-first, but many applications need server-side components for:

1. **Signaling and Relay**: WebRTC signaling, message relay when peers aren't online
2. **Encrypted Backups**: Store encrypted team graphs server-side (server can't decrypt)
3. **Discovery**: Help users find their teams across devices
4. **Spam Prevention**: Rate limiting and access control
5. **Analytics**: Track usage without accessing encrypted content

The key insight is that @localfirst/auth already provides everything needed for server authentication:

- Users have cryptographic identities (public/private keypairs)
- Challenge-response authentication is built-in
- Teams have unique identifiers in their graphs
- The library can verify signatures without accessing secrets

This guide shows how to build a registration server that **doesn't store passwords** and instead uses cryptographic signatures for authentication.

## Architecture

### Client-Side Components

- **User**: A person with a cryptographic identity (userId, userName, keys)
- **Device**: A physical device belonging to that user
- **Team**: A group of users with their own graph and keyring

### Server-Side Components

- **Registration Database**: Stores public information about registered users and teams
- **Authentication Service**: Verifies user identity using signature challenges
- **Rate Limiter**: Prevents spam and abuse
- **Backup Store**: Stores encrypted team graphs (encrypted by clients)
- **Signaling Service**: Relays messages between authenticated peers

### What the Server Knows vs. Doesn't Know

**Server KNOWS:**
- User IDs and usernames (public)
- Device IDs and names (public)
- Team IDs and names (public)
- Public keys for all users and devices
- Encrypted team graphs (but cannot decrypt them)
- Connection metadata (who's online, IP addresses, etc.)

**Server DOES NOT KNOW:**
- Private keys (never transmitted to server)
- Team content or membership details (only has encrypted graphs)
- Decrypted messages or documents
- Roles or permissions within teams

## Registration Flow

### Step 1: Client Prepares Registration

```typescript
import { createUser, createDevice, createTeam } from '@localfirst/auth'

// Create user and device
const user = createUser('alice')
const device = createDevice({
  userId: user.userId,
  deviceName: 'laptop'
})

// Create team
const team = createTeam('Alice Personal', { user, device })

// Prepare registration payload
const registrationPayload = {
  user: {
    userId: user.userId,
    userName: user.userName,
    keys: user.keys // Public keys only (redactKeys() if using UserWithSecrets)
  },
  device: {
    deviceId: device.deviceId,
    deviceName: device.deviceName,
    userId: device.userId,
    keys: device.keys // Public keys only
  },
  team: {
    teamId: team.id, // Unique identifier from the team graph
    teamName: team.teamName,
    serializedGraph: team.save() // Encrypted graph
  }
}
```

### Step 2: Client Proves Ownership

To prevent someone from registering arbitrary user IDs, the client must prove they own the private key:

```typescript
import { signatures } from '@localfirst/crypto'

// Server generates a challenge (random nonce + timestamp)
const response = await fetch('https://api.example.com/register/challenge', {
  method: 'POST',
  body: JSON.stringify({
    userId: user.userId
  })
})

const { challenge } = await response.json()
// challenge = { userId: 'abc123', nonce: 'xyz...', timestamp: 1234567890 }

// Client signs the challenge
const signature = signatures.sign(challenge, user.keys.signature.secretKey)

// Client sends registration with proof
await fetch('https://api.example.com/register', {
  method: 'POST',
  body: JSON.stringify({
    ...registrationPayload,
    challenge,
    signature
  })
})
```

### Step 3: Server Validates and Stores

```typescript
// Server validates the signature
import { signatures } from '@localfirst/crypto'

function validateRegistration(payload) {
  const { user, challenge, signature } = payload
  
  // Verify timestamp is recent (within 5 minutes)
  const now = Date.now()
  if (Math.abs(now - challenge.timestamp) > 5 * 60 * 1000) {
    throw new Error('Challenge expired')
  }
  
  // Verify signature using the user's public key
  const isValid = signatures.verify({
    payload: challenge,
    signature,
    publicKey: user.keys.signature
  })
  
  if (!isValid) {
    throw new Error('Invalid signature - cannot prove ownership of this user ID')
  }
  
  // Check if user is already registered
  if (db.users.findOne({ userId: user.userId })) {
    throw new Error('User already registered')
  }
  
  return true
}

// Store in database
async function registerUser(payload) {
  await validateRegistration(payload)
  
  const { user, device, team } = payload
  
  // Store user (public keys only)
  await db.users.insert({
    userId: user.userId,
    userName: user.userName,
    publicKeys: {
      signature: user.keys.signature,
      encryption: user.keys.encryption
    },
    registeredAt: new Date(),
    // For spam prevention
    rateLimit: {
      registrations: 1,
      lastRegistration: new Date()
    }
  })
  
  // Store device
  await db.devices.insert({
    deviceId: device.deviceId,
    deviceName: device.deviceName,
    userId: user.userId,
    publicKeys: device.keys
  })
  
  // Store team
  await db.teams.insert({
    teamId: team.teamId,
    teamName: team.teamName,
    founderId: user.userId,
    encryptedGraph: team.serializedGraph, // Server can't decrypt this
    createdAt: new Date()
  })
  
  // Store team membership
  await db.teamMembers.insert({
    teamId: team.teamId,
    userId: user.userId,
    role: 'founder',
    joinedAt: new Date()
  })
  
  return {
    success: true,
    userId: user.userId,
    teamId: team.teamId
  }
}
```

## Authentication Flow

Once registered, users authenticate to access services using the same challenge-response mechanism:

### Step 1: Client Requests Service Access

```typescript
// Client wants to connect to signaling service
const response = await fetch('https://api.example.com/auth/challenge', {
  method: 'POST',
  body: JSON.stringify({
    deviceId: device.deviceId
  })
})

const { challenge } = await response.json()
```

### Step 2: Client Proves Identity

```typescript
import { signatures } from '@localfirst/crypto'

// Sign challenge with device's private key
const proof = signatures.sign(challenge, device.keys.signature.secretKey)

// Send proof to get access token
const authResponse = await fetch('https://api.example.com/auth/verify', {
  method: 'POST',
  body: JSON.stringify({
    deviceId: device.deviceId,
    challenge,
    proof
  })
})

const { accessToken, expiresIn } = await authResponse.json()

// Use token for authenticated requests
const ws = new WebSocket('wss://signal.example.com', {
  headers: { Authorization: `Bearer ${accessToken}` }
})
```

### Step 3: Server Validates and Issues Token

```typescript
import jwt from 'jsonwebtoken'

async function authenticateDevice(payload) {
  const { deviceId, challenge, proof } = payload
  
  // Verify challenge is recent
  if (Date.now() - challenge.timestamp > 5 * 60 * 1000) {
    throw new Error('Challenge expired')
  }
  
  // Look up device public key
  const device = await db.devices.findOne({ deviceId })
  if (!device) {
    throw new Error('Device not registered')
  }
  
  // Verify signature
  const isValid = signatures.verify({
    payload: challenge,
    signature: proof,
    publicKey: device.publicKeys.signature
  })
  
  if (!isValid) {
    throw new Error('Invalid proof')
  }
  
  // Issue JWT token
  const token = jwt.sign(
    {
      deviceId: device.deviceId,
      userId: device.userId,
      type: 'device'
    },
    process.env.JWT_SECRET,
    { expiresIn: '24h' }
  )
  
  return {
    accessToken: token,
    expiresIn: 86400 // 24 hours in seconds
  }
}
```

## Implementation

### Database Schema

```typescript
// MongoDB/Postgres/etc schema

interface UserRecord {
  userId: string // Primary key
  userName: string
  publicKeys: {
    signature: string // Base58 encoded public key
    encryption: string
  }
  registeredAt: Date
  
  // Rate limiting
  rateLimit: {
    registrations: number // Total devices/teams registered
    lastRegistration: Date
    dailyAuthAttempts: number
    lastAuthAttempt: Date
  }
  
  // Optional: For account recovery
  email?: string // If provided and verified
  
  // Indexes
  _indexes: ['userId', 'userName', 'email']
}

interface DeviceRecord {
  deviceId: string // Primary key
  deviceName: string
  userId: string // Foreign key to UserRecord
  publicKeys: {
    signature: string
    encryption: string
  }
  registeredAt: Date
  lastSeen?: Date
  
  _indexes: ['deviceId', 'userId']
}

interface TeamRecord {
  teamId: string // Primary key (from team graph)
  teamName: string
  founderId: string // User who registered this team
  encryptedGraph: Uint8Array // Encrypted team graph
  graphVersion: number // Incremented on each backup
  createdAt: Date
  updatedAt: Date
  
  // For discovery
  isPublic: boolean
  inviteCode?: string // Optional public invite code
  
  _indexes: ['teamId', 'founderId', 'inviteCode']
}

interface TeamMemberRecord {
  teamId: string // Foreign key to TeamRecord
  userId: string // Foreign key to UserRecord
  role: 'founder' | 'admin' | 'member' // Application-level roles
  joinedAt: Date
  
  _indexes: ['teamId', 'userId', 'teamId,userId']
}

interface BackupRecord {
  teamId: string
  version: number
  encryptedGraph: Uint8Array
  uploadedBy: string // deviceId
  uploadedAt: Date
  size: number // bytes
  
  _indexes: ['teamId,version', 'uploadedAt']
}
```

### Express Server Implementation

```typescript
import express from 'express'
import rateLimit from 'express-rate-limit'
import { signatures } from '@localfirst/crypto'
import jwt from 'jsonwebtoken'

const app = express()
app.use(express.json())

// Rate limiting middleware
const registrationLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 3, // 3 registrations per IP per 15 minutes
  message: 'Too many registration attempts, please try again later'
})

const authLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 10, // 10 auth attempts per minute
  message: 'Too many authentication attempts'
})

// ============================================
// REGISTRATION ENDPOINTS
// ============================================

// Step 1: Request a challenge for registration
app.post('/register/challenge', registrationLimiter, async (req, res) => {
  const { userId } = req.body
  
  if (!userId) {
    return res.status(400).json({ error: 'userId required' })
  }
  
  // Generate challenge
  const challenge = {
    userId,
    nonce: randomKey(),
    timestamp: Date.now(),
    purpose: 'registration'
  }
  
  // Store challenge temporarily (5 minute expiry)
  await redis.setex(
    `challenge:${userId}`,
    300,
    JSON.stringify(challenge)
  )
  
  res.json({ challenge })
})

// Step 2: Register user with signed challenge
app.post('/register', registrationLimiter, async (req, res) => {
  try {
    const { user, device, team, challenge, signature } = req.body
    
    // Validate payload
    if (!user?.userId || !user?.keys?.signature) {
      return res.status(400).json({ error: 'Invalid user data' })
    }
    
    // Retrieve stored challenge
    const storedChallenge = await redis.get(`challenge:${user.userId}`)
    if (!storedChallenge) {
      return res.status(400).json({ error: 'Challenge not found or expired' })
    }
    
    // Verify challenge matches
    if (JSON.stringify(challenge) !== storedChallenge) {
      return res.status(400).json({ error: 'Challenge mismatch' })
    }
    
    // Verify signature
    const isValid = signatures.verify({
      payload: challenge,
      signature,
      publicKey: user.keys.signature
    })
    
    if (!isValid) {
      return res.status(403).json({ error: 'Invalid signature' })
    }
    
    // Check if already registered
    const existing = await db.users.findOne({ userId: user.userId })
    if (existing) {
      return res.status(409).json({ error: 'User already registered' })
    }
    
    // Register user, device, and team
    await registerUser({ user, device, team })
    
    // Delete used challenge
    await redis.del(`challenge:${user.userId}`)
    
    res.json({
      success: true,
      userId: user.userId,
      deviceId: device.deviceId,
      teamId: team.teamId
    })
    
  } catch (error) {
    console.error('Registration error:', error)
    res.status(500).json({ error: error.message })
  }
})

// ============================================
// AUTHENTICATION ENDPOINTS
// ============================================

// Step 1: Request authentication challenge
app.post('/auth/challenge', authLimiter, async (req, res) => {
  const { deviceId } = req.body
  
  // Check device exists
  const device = await db.devices.findOne({ deviceId })
  if (!device) {
    return res.status(404).json({ error: 'Device not registered' })
  }
  
  // Generate challenge
  const challenge = {
    type: 'DEVICE',
    name: deviceId,
    nonce: randomKey(),
    timestamp: Date.now()
  }
  
  // Store temporarily
  await redis.setex(
    `auth:${deviceId}`,
    300,
    JSON.stringify(challenge)
  )
  
  res.json({ challenge })
})

// Step 2: Verify proof and issue token
app.post('/auth/verify', authLimiter, async (req, res) => {
  try {
    const { deviceId, challenge, proof } = req.body
    
    // Retrieve stored challenge
    const storedChallenge = await redis.get(`auth:${deviceId}`)
    if (!storedChallenge) {
      return res.status(400).json({ error: 'Challenge not found or expired' })
    }
    
    // Verify challenge matches
    if (JSON.stringify(challenge) !== storedChallenge) {
      return res.status(400).json({ error: 'Challenge mismatch' })
    }
    
    // Look up device
    const device = await db.devices.findOne({ deviceId })
    if (!device) {
      return res.status(404).json({ error: 'Device not found' })
    }
    
    // Verify signature
    const isValid = signatures.verify({
      payload: challenge,
      signature: proof,
      publicKey: device.publicKeys.signature
    })
    
    if (!isValid) {
      return res.status(403).json({ error: 'Invalid proof' })
    }
    
    // Issue JWT
    const token = jwt.sign(
      {
        deviceId: device.deviceId,
        userId: device.userId
      },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    )
    
    // Update last seen
    await db.devices.updateOne(
      { deviceId },
      { $set: { lastSeen: new Date() } }
    )
    
    // Delete used challenge
    await redis.del(`auth:${deviceId}`)
    
    res.json({
      accessToken: token,
      expiresIn: 86400
    })
    
  } catch (error) {
    console.error('Auth error:', error)
    res.status(500).json({ error: error.message })
  }
})

// Middleware to verify JWT tokens
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' })
  }
  
  const token = authHeader.substring(7)
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET)
    req.auth = decoded
    next()
  } catch (error) {
    res.status(401).json({ error: 'Invalid or expired token' })
  }
}

// ============================================
// BACKUP ENDPOINTS (requires authentication)
// ============================================

app.post('/backups/:teamId', requireAuth, async (req, res) => {
  try {
    const { teamId } = req.params
    const { encryptedGraph } = req.body
    
    // Verify user is member of this team
    const membership = await db.teamMembers.findOne({
      teamId,
      userId: req.auth.userId
    })
    
    if (!membership) {
      return res.status(403).json({ error: 'Not a member of this team' })
    }
    
    // Get current version
    const team = await db.teams.findOne({ teamId })
    const newVersion = (team?.graphVersion || 0) + 1
    
    // Store backup
    await db.backups.insert({
      teamId,
      version: newVersion,
      encryptedGraph,
      uploadedBy: req.auth.deviceId,
      uploadedAt: new Date(),
      size: encryptedGraph.length
    })
    
    // Update team record
    await db.teams.updateOne(
      { teamId },
      {
        $set: {
          encryptedGraph,
          graphVersion: newVersion,
          updatedAt: new Date()
        }
      }
    )
    
    res.json({
      success: true,
      version: newVersion
    })
    
  } catch (error) {
    console.error('Backup error:', error)
    res.status(500).json({ error: error.message })
  }
})

app.get('/backups/:teamId', requireAuth, async (req, res) => {
  try {
    const { teamId } = req.params
    const { version } = req.query
    
    // Verify membership
    const membership = await db.teamMembers.findOne({
      teamId,
      userId: req.auth.userId
    })
    
    if (!membership) {
      return res.status(403).json({ error: 'Not a member of this team' })
    }
    
    if (version) {
      // Get specific version
      const backup = await db.backups.findOne({ teamId, version: parseInt(version) })
      if (!backup) {
        return res.status(404).json({ error: 'Version not found' })
      }
      res.json(backup)
    } else {
      // Get latest
      const team = await db.teams.findOne({ teamId })
      res.json({
        teamId: team.teamId,
        version: team.graphVersion,
        encryptedGraph: team.encryptedGraph,
        updatedAt: team.updatedAt
      })
    }
    
  } catch (error) {
    console.error('Backup retrieval error:', error)
    res.status(500).json({ error: error.message })
  }
})

// ============================================
// SIGNALING SERVICE (WebSocket)
// ============================================

import { WebSocketServer } from 'ws'

const wss = new WebSocketServer({ noServer: true })

// Upgrade HTTP server to handle WebSocket
server.on('upgrade', async (request, socket, head) => {
  try {
    // Extract token from query string or header
    const url = new URL(request.url, 'ws://localhost')
    const token = url.searchParams.get('token')
    
    if (!token) {
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n')
      socket.destroy()
      return
    }
    
    // Verify JWT
    const decoded = jwt.verify(token, process.env.JWT_SECRET)
    
    wss.handleUpgrade(request, socket, head, (ws) => {
      ws.userId = decoded.userId
      ws.deviceId = decoded.deviceId
      wss.emit('connection', ws, request)
    })
    
  } catch (error) {
    socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n')
    socket.destroy()
  }
})

// Handle WebSocket connections
wss.on('connection', (ws) => {
  console.log(`Device ${ws.deviceId} connected`)
  
  ws.on('message', (data) => {
    try {
      const message = JSON.parse(data)
      
      // Relay message to target peer
      if (message.to) {
        const targetWs = Array.from(wss.clients).find(
          client => client.deviceId === message.to
        )
        
        if (targetWs && targetWs.readyState === WebSocket.OPEN) {
          targetWs.send(JSON.stringify({
            from: ws.deviceId,
            payload: message.payload
          }))
        }
      }
      
    } catch (error) {
      console.error('Message error:', error)
    }
  })
  
  ws.on('close', () => {
    console.log(`Device ${ws.deviceId} disconnected`)
  })
})

app.listen(3000, () => {
  console.log('Server running on port 3000')
})
```

## Spam Prevention

### Rate Limiting Strategies

```typescript
// Per-IP rate limits
const ipLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10, // 10 registrations per IP per 15 minutes
  standardHeaders: true,
  legacyHeaders: false,
})

// Per-user rate limits (check in DB)
async function checkUserRateLimit(userId) {
  const user = await db.users.findOne({ userId })
  
  if (!user) return true // New user
  
  const limits = user.rateLimit
  const now = new Date()
  
  // Max 5 devices per user
  const deviceCount = await db.devices.countDocuments({ userId })
  if (deviceCount >= 5) {
    throw new Error('Maximum devices reached')
  }
  
  // Max 3 teams per user in first 24 hours
  if (now - user.registeredAt < 24 * 60 * 60 * 1000) {
    const teamCount = await db.teamMembers.countDocuments({ userId })
    if (teamCount >= 3) {
      throw new Error('Rate limit: too many teams created')
    }
  }
  
  return true
}

// CAPTCHA verification for suspicious activity
async function requireCaptchaIfSuspicious(req) {
  const ip = req.ip
  
  // Check if IP has high registration rate
  const recentRegistrations = await redis.get(`registrations:${ip}`)
  
  if (parseInt(recentRegistrations) > 3) {
    // Require CAPTCHA
    const { captchaToken } = req.body
    
    if (!captchaToken) {
      throw new Error('CAPTCHA required')
    }
    
    // Verify CAPTCHA with service like hCaptcha or reCAPTCHA
    const isValid = await verifyCaptcha(captchaToken)
    if (!isValid) {
      throw new Error('Invalid CAPTCHA')
    }
  }
  
  // Track registration
  await redis.incr(`registrations:${ip}`)
  await redis.expire(`registrations:${ip}`, 3600) // 1 hour
}
```

### Cost-Based Rate Limiting

```typescript
// Different operations have different "costs"
const COSTS = {
  register: 10,
  auth: 1,
  backup: 5,
  download: 2,
}

async function checkCostBudget(userId, operation) {
  const key = `budget:${userId}:${getCurrentHour()}`
  const budget = 100 // 100 points per hour
  
  const used = await redis.get(key) || 0
  const cost = COSTS[operation]
  
  if (used + cost > budget) {
    throw new Error('Rate limit exceeded')
  }
  
  await redis.incrby(key, cost)
  await redis.expire(key, 3600)
}
```

### Email Verification (Optional)

```typescript
// Optional: Require email verification for higher limits
async function sendVerificationEmail(user, email) {
  const token = randomKey()
  
  await db.verifications.insert({
    userId: user.userId,
    email,
    token,
    expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000)
  })
  
  await sendEmail({
    to: email,
    subject: 'Verify your email',
    body: `Click here to verify: https://example.com/verify?token=${token}`
  })
}

// Verified users get higher limits
async function getUserLimits(userId) {
  const user = await db.users.findOne({ userId })
  
  if (user.emailVerified) {
    return {
      maxDevices: 20,
      maxTeams: 50,
      backupSizeLimit: 100 * 1024 * 1024, // 100MB
    }
  } else {
    return {
      maxDevices: 5,
      maxTeams: 10,
      backupSizeLimit: 10 * 1024 * 1024, // 10MB
    }
  }
}
```

## Use Cases

### 1. Encrypted Backup Service

```typescript
// Client: Automatically backup team graph
team.on('updated', async () => {
  const encryptedGraph = team.save()
  
  await fetch('https://api.example.com/backups/my-team-id', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ encryptedGraph })
  })
})

// Client: Restore from backup on new device
async function restoreFromBackup(teamId, user, device, teamKeyring) {
  const response = await fetch(`https://api.example.com/backups/${teamId}`, {
    headers: { 'Authorization': `Bearer ${accessToken}` }
  })
  
  const { encryptedGraph } = await response.json()
  
  const team = new Team({
    source: encryptedGraph,
    teamKeyring,
    context: { user, device }
  })
  
  return team
}
```

### 2. Team Discovery

```typescript
// Server: Public team discovery endpoint
app.get('/teams/discover', requireAuth, async (req, res) => {
  const { query } = req.query
  
  // Search public teams
  const teams = await db.teams.find({
    isPublic: true,
    teamName: { $regex: query, $options: 'i' }
  }).limit(20)
  
  res.json({
    teams: teams.map(t => ({
      teamId: t.teamId,
      teamName: t.teamName,
      memberCount: t.memberCount,
      inviteCode: t.inviteCode
    }))
  })
})

// Client: Join public team
async function joinPublicTeam(inviteCode) {
  // Look up team
  const response = await fetch(
    `https://api.example.com/teams/by-code/${inviteCode}`
  )
  const { teamId } = await response.json()
  
  // Connect to team member to join
  // (standard invitation flow from here)
}
```

### 3. Cross-Device Team Sync

```typescript
// Client: When app starts, sync all teams from server
async function syncTeams(userId, accessToken) {
  // Get list of teams user is member of
  const response = await fetch(
    `https://api.example.com/users/${userId}/teams`,
    {
      headers: { 'Authorization': `Bearer ${accessToken}` }
    }
  )
  
  const { teams } = await response.json()
  
  // For each team, get latest backup
  for (const teamInfo of teams) {
    const backupResponse = await fetch(
      `https://api.example.com/backups/${teamInfo.teamId}`,
      {
        headers: { 'Authorization': `Bearer ${accessToken}` }
      }
    )
    
    const { encryptedGraph, version } = await backupResponse.json()
    
    // Load or update local team
    const localVersion = getLocalTeamVersion(teamInfo.teamId)
    
    if (version > localVersion) {
      // Server has newer version
      await updateLocalTeam(teamInfo.teamId, encryptedGraph)
    } else if (localVersion > version) {
      // Local is newer - upload backup
      const team = loadLocalTeam(teamInfo.teamId)
      await uploadBackup(team)
    }
  }
}
```

### 4. Signaling for WebRTC

```typescript
// Client: Connect to signaling server
const token = await authenticate(device)
const ws = new WebSocket(`wss://signal.example.com?token=${token}`)

// Use for WebRTC signaling
const connection = new Connection({
  sendMessage: (message) => {
    ws.send(JSON.stringify({
      to: peerDeviceId,
      payload: message
    }))
  },
  context: { user, device, team }
})

ws.onmessage = (event) => {
  const { from, payload } = JSON.parse(event.data)
  connection.receive(payload)
}
```

## Security Considerations

### 1. Never Store Private Keys

The server must **never** receive or store private keys. All authentication is done via challenge-response using public keys.

```typescript
// ❌ BAD: Never do this
app.post('/register', (req, res) => {
  const { user } = req.body
  db.users.insert({
    userId: user.userId,
    privateKey: user.keys.signature.secretKey // NEVER STORE THIS
  })
})

// ✅ GOOD: Only store public keys
app.post('/register', (req, res) => {
  const { user } = req.body
  db.users.insert({
    userId: user.userId,
    publicKeys: {
      signature: user.keys.signature, // Public key only
      encryption: user.keys.encryption
    }
  })
})
```

### 2. Encrypted Backups

The server stores encrypted team graphs but cannot decrypt them:

```typescript
// Server has the encrypted graph
const team = await db.teams.findOne({ teamId })
console.log(team.encryptedGraph) // Uint8Array of encrypted data

// Server CANNOT decrypt this without:
// - Team keyring (only team members have this)
// - Device keys (never transmitted to server)

// Only the client can decrypt:
const decryptedTeam = new Team({
  source: encryptedGraph,
  teamKeyring, // Only client has this
  context: { user, device } // Only client has these keys
})
```

### 3. Challenge Replay Prevention

Challenges must be:
- Time-limited (5 minute expiry)
- Single-use (deleted after verification)
- Tied to a specific purpose

```typescript
// Store challenge with short TTL
await redis.setex(
  `challenge:${userId}:${nonce}`,
  300, // 5 minutes
  JSON.stringify(challenge)
)

// After verification, delete immediately
await redis.del(`challenge:${userId}:${nonce}`)

// Future attempts with same challenge fail
```

### 4. Token Security

JWTs should:
- Have short expiry (24 hours or less)
- Include minimal information
- Be validated on every request

```typescript
// Issue short-lived tokens
const token = jwt.sign(
  {
    deviceId: device.deviceId,
    userId: device.userId,
    // Don't include sensitive data
  },
  process.env.JWT_SECRET,
  { expiresIn: '24h' } // Short expiry
)

// Validate on every protected endpoint
function requireAuth(req, res, next) {
  try {
    const token = extractToken(req)
    const decoded = jwt.verify(token, process.env.JWT_SECRET)
    
    // Optional: Check if device is still registered
    const device = await db.devices.findOne({ deviceId: decoded.deviceId })
    if (!device) {
      return res.status(401).json({ error: 'Device not found' })
    }
    
    req.auth = decoded
    next()
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' })
  }
}
```

### 5. Protect Against Account Takeover

Even without passwords, prevent takeover attempts:

```typescript
// Rate limit auth attempts per device
const authAttempts = await redis.incr(`auth:attempts:${deviceId}`)
await redis.expire(`auth:attempts:${deviceId}`, 3600)

if (authAttempts > 10) {
  // Require additional verification
  throw new Error('Too many attempts. Email verification required.')
}

// Track unusual activity
async function detectSuspiciousActivity(deviceId) {
  const device = await db.devices.findOne({ deviceId })
  const lastIp = device.lastIp
  const currentIp = req.ip
  
  if (lastIp && lastIp !== currentIp) {
    // Different IP - might be suspicious
    await notifyUser(device.userId, {
      message: `New login from ${currentIp}`,
      device: device.deviceName
    })
  }
}
```

## Complete Example

Here's a complete working example of a client registering and using authenticated services:

```typescript
// ============================================
// CLIENT SIDE
// ============================================

import { createUser, createDevice, createTeam } from '@localfirst/auth'
import { signatures } from '@localfirst/crypto'

const API_URL = 'https://api.example.com'

class AuthClient {
  constructor(user, device) {
    this.user = user
    this.device = device
    this.accessToken = null
  }
  
  // Register user, device, and team
  async register(teamName) {
    // Step 1: Request challenge
    const challengeRes = await fetch(`${API_URL}/register/challenge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userId: this.user.userId })
    })
    
    const { challenge } = await challengeRes.json()
    
    // Step 2: Sign challenge
    const signature = signatures.sign(
      challenge,
      this.user.keys.signature.secretKey
    )
    
    // Step 3: Create team
    const team = createTeam(teamName, {
      user: this.user,
      device: this.device
    })
    
    // Step 4: Register
    const registerRes = await fetch(`${API_URL}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user: {
          userId: this.user.userId,
          userName: this.user.userName,
          keys: {
            signature: this.user.keys.signature,
            encryption: this.user.keys.encryption
          }
        },
        device: {
          deviceId: this.device.deviceId,
          deviceName: this.device.deviceName,
          userId: this.device.userId,
          keys: this.device.keys
        },
        team: {
          teamId: team.id,
          teamName: team.teamName,
          serializedGraph: team.save()
        },
        challenge,
        signature
      })
    })
    
    if (!registerRes.ok) {
      throw new Error('Registration failed')
    }
    
    return await registerRes.json()
  }
  
  // Authenticate and get access token
  async authenticate() {
    // Step 1: Request challenge
    const challengeRes = await fetch(`${API_URL}/auth/challenge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ deviceId: this.device.deviceId })
    })
    
    const { challenge } = await challengeRes.json()
    
    // Step 2: Sign challenge
    const proof = signatures.sign(
      challenge,
      this.device.keys.signature.secretKey
    )
    
    // Step 3: Verify and get token
    const verifyRes = await fetch(`${API_URL}/auth/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        deviceId: this.device.deviceId,
        challenge,
        proof
      })
    })
    
    if (!verifyRes.ok) {
      throw new Error('Authentication failed')
    }
    
    const { accessToken, expiresIn } = await verifyRes.json()
    this.accessToken = accessToken
    
    // Auto-refresh before expiry
    setTimeout(() => this.authenticate(), (expiresIn - 60) * 1000)
    
    return accessToken
  }
  
  // Upload encrypted backup
  async uploadBackup(team) {
    if (!this.accessToken) {
      await this.authenticate()
    }
    
    const response = await fetch(`${API_URL}/backups/${team.id}`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.accessToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        encryptedGraph: team.save()
      })
    })
    
    return await response.json()
  }
  
  // Download encrypted backup
  async downloadBackup(teamId) {
    if (!this.accessToken) {
      await this.authenticate()
    }
    
    const response = await fetch(`${API_URL}/backups/${teamId}`, {
      headers: {
        'Authorization': `Bearer ${this.accessToken}`
      }
    })
    
    return await response.json()
  }
  
  // Connect to signaling server
  async connectSignaling() {
    if (!this.accessToken) {
      await this.authenticate()
    }
    
    const ws = new WebSocket(
      `wss://signal.example.com?token=${this.accessToken}`
    )
    
    return new Promise((resolve, reject) => {
      ws.onopen = () => resolve(ws)
      ws.onerror = reject
    })
  }
}

// ============================================
// USAGE
// ============================================

async function main() {
  // Create user and device
  const user = createUser('alice')
  const device = createDevice({
    userId: user.userId,
    deviceName: 'laptop'
  })
  
  // Initialize client
  const client = new AuthClient(user, device)
  
  // Register
  console.log('Registering...')
  const registration = await client.register('Alice Personal')
  console.log('Registered:', registration)
  
  // Save locally
  localStorage.setItem('user', JSON.stringify(user))
  localStorage.setItem('device', JSON.stringify(device))
  
  // Authenticate
  console.log('Authenticating...')
  await client.authenticate()
  console.log('Authenticated!')
  
  // Create a team (or load existing)
  const team = createTeam('My Team', { user, device })
  
  // Upload backup
  console.log('Uploading backup...')
  await client.uploadBackup(team)
  console.log('Backup uploaded!')
  
  // Connect to signaling
  const ws = await client.connectSignaling()
  console.log('Connected to signaling server')
  
  // Use signaling for peer connections
  ws.onmessage = (event) => {
    const { from, payload } = JSON.parse(event.data)
    console.log('Message from', from, ':', payload)
  }
  
  // On another device...
  
  // Restore from backup
  const user2 = JSON.parse(localStorage.getItem('user'))
  const device2 = createDevice({
    userId: user2.userId,
    deviceName: 'phone'
  })
  const client2 = new AuthClient(user2, device2)
  
  await client2.authenticate()
  const { encryptedGraph } = await client2.downloadBackup(team.id)
  
  const teamKeyring = JSON.parse(localStorage.getItem('teamKeyring'))
  const restoredTeam = new Team({
    source: encryptedGraph,
    teamKeyring,
    context: { user: user2, device: device2 }
  })
  
  console.log('Team restored:', restoredTeam.teamName)
}

main().catch(console.error)
```

## See Also

- [Multi-Device Usage](./multi-device-and-sharing.md)
- [Team API Documentation](./team.md)
- [Connection Protocol](./connection.md)
- [Sync Server Implementation](../packages/auth-syncserver/README.md)

