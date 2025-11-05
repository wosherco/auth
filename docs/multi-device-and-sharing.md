# Multi-Device Usage and Cross-Team Sharing

This guide explains how to properly use @localfirst/auth across multiple devices and how to implement access control and sharing patterns.

## Architecture: Users vs Devices

### The Correct Model

The library is designed with this hierarchy:

- **USER** = A person
- **DEVICE** = A physical device (laptop, phone, tablet, etc.) belonging to that person
- **TEAM** = A group of users collaborating together

### ❌ Anti-pattern: One User Per Device

**Don't do this:**

```js
// WRONG: Creating separate users for each device
const laptopUser = createUser('pol-laptop')
const desktopUser = createUser('pol-desktop')
const phoneUser = createUser('pol-phone')
```

**Problems with this approach:**

- Each "user" would need to be invited separately
- You'd have multiple identities instead of one
- Removing a lost device would require removing a "user" and rotating keys
- No shared identity across your devices

### ✅ Correct Pattern: One User, Multiple Devices

**Do this instead:**

```js
// CORRECT: One user, multiple devices
const user = createUser('pol')

const laptop = createDevice({
  userId: user.userId,
  deviceName: 'laptop'
})

const desktop = createDevice({
  userId: user.userId,
  deviceName: 'desktop'
})
```

## Setting Up Multiple Devices

### Step 1: Create Team on First Device

On your first device (e.g., laptop):

```js
import { createTeam, createUser, createDevice } from '@localfirst/auth'

// Create your user identity
const user = createUser('pol')

// Create the first device
const laptop = createDevice({
  userId: user.userId,
  deviceName: 'laptop'
})

// Create the team
const team = createTeam('My Personal Workspace', {
  user,
  device: laptop
})

// Save the team graph and user info
localStorage.setItem('team', team.save())
localStorage.setItem('user', JSON.stringify(user))
```

### Step 2: Invite Your Second Device

Still on your first device:

```js
// Generate a device invitation
const { id, seed } = team.inviteDevice({
  expiration: Date.now() + 30 * 60 * 1000 // 30 minutes
})

console.log('Invitation code:', seed)
// Or generate a QR code containing the seed
```

**Transfer the seed to your second device:**

- Display as QR code and scan with phone
- Type it manually
- Copy via secure channel

### Step 3: Join from Second Device

On your second device (e.g., desktop):

```js
import { createDevice, Connection } from '@localfirst/auth'
import { generateProof } from '@localfirst/auth/invitation'

// The invitation seed from step 2
const invitationSeed = 'the-seed-from-laptop'

// Create this device
const desktop = createDevice({
  userId: 'not-known-yet', // Will be populated when admitted
  deviceName: 'desktop'
})

// Generate proof of invitation
const proof = generateProof(invitationSeed)

// Connect to your first device (or any team member)
const connection = new Connection({
  sendMessage: (message) => {
    // Send to laptop via WebSocket, WebRTC, etc.
    socket.send(message)
  },
  context: {
    userName: 'pol', // Your username
    device: desktop,
    invitationSeed
  }
})

// Listen for successful join
connection.on('joined', ({ team, user, teamKeyring }) => {
  // Save everything
  localStorage.setItem('team', team.save())
  localStorage.setItem('user', JSON.stringify(user))
  localStorage.setItem('teamKeyring', JSON.stringify(teamKeyring))
  
  // Now you can use the team!
  console.log('Successfully joined!')
})

connection.start()

// Feed incoming messages from the peer
socket.on('message', (message) => {
  connection.receive(message)
})
```

### Step 4: Join the Team

After the connection authenticates and you receive the team graph:

```js
connection.on('joined', ({ team, user, userKeyring }) => {
  // Complete the join process by adding your device
  team.join(teamKeyring, userKeyring)
  
  // Save updated team with your device added
  localStorage.setItem('team', team.save())
})
```

### Step 5: Add More Devices

Repeat steps 2-4 for each additional device (phone, tablet, etc.).

## Managing Devices

### List Your Devices

```js
const myDevices = team.members(user.userId).devices
console.log('My devices:', myDevices.map(d => d.deviceName))
```

### Remove a Lost Device

```js
// If you lose your phone, remove it from any other device
const phoneDevice = myDevices.find(d => d.deviceName === 'phone')
team.removeDevice(phoneDevice.deviceId)

// This triggers key rotation - the phone can no longer decrypt new content
```

## Access Control and Sharing Patterns

### Pattern 1: Role-Based Access Control (Recommended)

Use roles within a single team for most ACL scenarios:

```js
// Create roles for different access levels
team.addRole('documents')
team.addRole('photos')
team.addRole('finance')

// You automatically have all roles as the founder
// Later, you can invite others with specific roles

// Encrypt content for specific roles
const financialDoc = team.encrypt(documentData, 'finance')
const photo = team.encrypt(photoData, 'photos')

// Decrypt (only works if you have the role)
const decryptedDoc = team.decrypt(financialDoc)
```

**Use cases:**

- Personal organization (work docs, personal docs, etc.)
- Family sharing (kids can access 'family-photos' but not 'finance')
- Project-based access (different roles for different projects)

### Pattern 2: Multiple Teams

You can be a member of multiple independent teams:

```js
// Load and manage multiple teams
const personalTeam = new Team({
  source: loadTeamGraph('personal'),
  teamKeyring: loadKeyring('personal'),
  context: { user, device }
})

const workTeam = new Team({
  source: loadTeamGraph('work'),
  teamKeyring: loadKeyring('work'),
  context: { user, device }
})

const familyTeam = new Team({
  source: loadTeamGraph('family'),
  teamKeyring: loadKeyring('family'),
  context: { user, device }
})

// Each team has independent:
// - Members
// - Keys
// - Encrypted content
// - Team graph
```

**Use cases:**

- Strict separation of concerns (personal vs work)
- Different groups of collaborators
- Regulatory/compliance requirements

### Pattern 3: Selective Member Invitation

Invite people to your team and control their access via roles:

```js
// Invite a family member
const { seed } = team.inviteMember()
// Share seed with family member via trusted channel

// When they connect, admit them with limited roles
team.on('connection', (connection) => {
  connection.on('identityClaim', async ({ proof, memberKeys, userName }) => {
    // Admit them
    team.admitMember(proof, memberKeys, userName)
    
    // Give them specific roles
    const newMember = team.members().find(m => m.userName === userName)
    team.addMemberRole(newMember.userId, 'family-photos')
    // Note: NOT adding them to 'finance' role
  })
})
```

### Pattern 4: Cross-Team Sharing (Advanced)

For sharing specific content across teams, use direct asymmetric encryption:

```js
import { asymmetric } from '@localfirst/crypto'

// You're in Team A, want to share with Bob in Team B

// 1. Get Bob's public key (you need to exchange this somehow)
const bobsPublicKey = 'Bob4FPKvH8...' // Bob shares this out-of-band

// 2. Encrypt content for Bob
const encrypted = asymmetric.encrypt(
  contentData,
  myUser.keys.encryption.secretKey, // Your private key
  bobsPublicKey // Bob's public key
)

// 3. Send encrypted content to Bob (via any channel)

// Bob decrypts:
const decrypted = asymmetric.decrypt(
  encrypted,
  bobsUser.keys.encryption.secretKey, // Bob's private key
  yourPublicKey // Your public key
)
```

**Use cases:**

- One-off sharing between teams
- Public key infrastructure (PKI) style sharing
- Guest access patterns

## Example: Complete Multi-Device Personal Setup

Here's a complete example for a personal workspace across devices:

```js
// ============================================
// LAPTOP (First Device)
// ============================================

import { createTeam, createUser, createDevice } from '@localfirst/auth'

const user = createUser('pol')
const laptop = createDevice({ userId: user.userId, deviceName: 'laptop' })
const team = createTeam('Personal Workspace', { user, device: laptop })

// Organize with roles
team.addRole('work')
team.addRole('personal')
team.addRole('finance')

// Store work document
const workDoc = team.encrypt({ 
  title: 'Q4 Report',
  content: '...' 
}, 'work')

// Store personal note
const note = team.encrypt({
  title: 'Grocery List',
  content: '...'
}, 'personal')

// Invite desktop
const { seed: desktopSeed } = team.inviteDevice()
console.log('Desktop invitation:', desktopSeed)


// ============================================
// DESKTOP (Second Device)
// ============================================

const desktop = createDevice({ 
  userId: user.userId, // Same user!
  deviceName: 'desktop' 
})

const connection = new Connection({
  sendMessage: (msg) => sendToLaptop(msg),
  context: {
    userName: 'pol',
    device: desktop,
    invitationSeed: desktopSeed
  }
})

connection.on('joined', ({ team, user, teamKeyring, userKeyring }) => {
  // Join the team
  team.join(teamKeyring, userKeyring)
  
  // Now you can decrypt everything on desktop too!
  const workDoc = team.decrypt(workDocEncrypted)
  const note = team.decrypt(noteEncrypted)
  
  console.log('Synced across devices!')
})

connection.start()


// ============================================
// PHONE (Third Device)
// ============================================

// Same process as desktop
// Generate QR code with invitation seed
// Scan with phone
// Phone joins team
// All content syncs!
```

## Best Practices

### 1. Device Naming

Use descriptive device names:

```js
createDevice({
  userId: user.userId,
  deviceName: 'Macbook Pro 2023',
  deviceInfo: {
    os: 'macOS',
    browser: 'Chrome',
    location: 'Home Office'
  }
})
```

### 2. Invitation Expiration

Use short expiration times for device invitations:

```js
// 30 minutes is reasonable for device setup
const { seed } = team.inviteDevice({
  expiration: Date.now() + 30 * 60 * 1000
})

// For member invitations, you might want longer
const { seed: memberSeed } = team.inviteMember({
  expiration: Date.now() + 24 * 60 * 60 * 1000 // 24 hours
})
```

### 3. Regular Cleanup

Periodically review and remove old devices:

```js
const myDevices = team.members(user.userId).devices

// Remove devices you no longer use
const oldDevices = myDevices.filter(d => {
  const age = Date.now() - d.created
  const sixMonths = 180 * 24 * 60 * 60 * 1000
  return age > sixMonths && !d.isCurrentDevice
})

oldDevices.forEach(d => team.removeDevice(d.deviceId))
```

### 4. Backup Your Seed

Your initial user keys are critical. Consider backing up the seed:

```js
// When creating the user, specify a seed
const seed = 'your-backed-up-seed-phrase'
const user = createUser('pol', seed)

// Store this seed phrase securely (password manager, encrypted backup)
// You can use it to recover your identity on a new device
```

## Security Considerations

1. **Device Keys Never Leave the Device**: Each device has its own keys that authenticate it. These should never be transferred.

2. **User Keys Are Shared**: Your user keys are shared across your devices via encrypted lockboxes. This is by design.

3. **Key Rotation on Device Removal**: When you remove a device, all keys it had access to are rotated. The removed device cannot decrypt new content.

4. **Invitation Seeds Are Sensitive**: Treat invitation seeds like passwords. Use secure channels to transfer them.

5. **Connection Security**: The connection protocol establishes a session key for each connection, providing forward secrecy.

## Common Questions

**Q: Can I add a device without connecting to another device?**  
A: No, you need to connect to at least one existing team member to join. This is a security feature - it prevents unauthorized devices from joining.

**Q: What if all my devices are lost?**  
A: If you backed up your team graph and user seed, you can restore on a new device. Otherwise, the team is unrecoverable.

**Q: Can I transfer a device to another user?**  
A: No. Devices are tied to users. You should remove the device from your account, then the other person creates their own device and joins as a new member.

**Q: How many devices can I have?**  
A: There's no hard limit, but each device adds some overhead to key rotation. Dozens of devices per user is fine.

**Q: Can a device be in multiple teams?**  
A: Yes! A device can be used to access multiple teams. Each team is independent.

## See Also

- [Team API Documentation](./team.md)
- [Connection Protocol](./connection.md)
- [Invitation System](./invitations.md)
- [Lockboxes and Key Distribution](./lockbox.md)

