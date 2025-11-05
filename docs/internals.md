# Internals

## 👩🏾📱 Users, devices, and keys

In this system, authentication and authorization are based on cryptographic keys organized in a hierarchy:

### Users

A **user** represents a person who is a member of a team. Each user has:

- `userId`: A unique identifier (CUID)
- `userName`: A human-readable name or email (must be unique within the team)
- `keys`: A keyset containing cryptographic keys

### Devices

Each user can have multiple **devices** (laptop, phone, tablet, etc.). Each device has:

- `deviceId`: A unique identifier (CUID)
- `deviceName`: A human-readable name (e.g. "Alice's laptop")
- `userId`: The ID of the user who owns this device
- `keys`: A separate keyset for this device
- `deviceInfo`: Optional metadata about the device
- `created`: Timestamp when the device was added

Devices authenticate independently of their users. When a device connects to the team, it proves its identity using its own keys, not the user's keys.

### Keysets

A **keyset** is a collection of cryptographic keys used for different purposes. Each keyset contains:

- **`secretKey`**: A symmetric encryption key (32 bytes) for encrypting/decrypting content
- **`encryption`**: An asymmetric keypair for encrypting content for specific recipients
  - `publicKey`: Can be shared publicly
  - `secretKey`: Must be kept private
- **`signature`**: An asymmetric keypair for signing and verifying content
  - `publicKey`: Can be shared publicly
  - `secretKey`: Must be kept private

All keys are generated from a single 32-byte random seed using a key derivation process based on [Keybase's Per-User Keys](http://keybase.io/docs/teams/puk).

### Key metadata

Each keyset also includes metadata:

- **`type`**: The scope of the keys (e.g. `USER`, `DEVICE`, `TEAM`, `ROLE`, `SERVER`, `EPHEMERAL`)
- **`name`**: An identifier within that scope (e.g. user ID, device ID, role name)
- **`generation`**: A version number, incremented when keys are rotated

### Key types

Different entities in the system have their own keysets:

- **Team keys**: Shared among all team members (stored in lockboxes)
- **Role keys**: Shared among members of a specific role (e.g. "admin", "manager")
- **User keys**: Belong to a specific user, shared across their devices (stored in lockboxes)
- **Device keys**: Unique to each device, never leave the device
- **Server keys**: Used by sync servers, act as both user and device keys
- **Ephemeral keys**: Temporary, single-use keys (e.g. for lockbox encryption)

### Secret management

- **Device keys** are the only keys that are stored in plaintext on the device
- All other keys (user, team, role) are encrypted in **lockboxes** and distributed via the team graph
- When a device joins a team, it uses its device keys to unlock lockboxes containing the user's keys
- When a user joins a team, they use their user keys to unlock lockboxes containing team and role keys

### Key rotation

When a member, device, or role is removed from a team, any keys they had access to are considered **compromised** and must be rotated:

1. Generate new keys for the compromised scope
2. Identify all keys visible from that scope (the "key graph")
3. Generate new keys for all visible scopes
4. Create new lockboxes for all affected recipients
5. Post the new lockboxes to the team graph

This ensures that removed members or devices can no longer decrypt new content.

## 📪⚛️ The CRDX store

###

TODO

### Action types

TODO

### The reducer

TODO

### The resolver

TODO

## 💌💌 Invitations

TODO

## 🔐📦 Lockboxes

A lockbox allows you to **encrypt content once for multiple readers**.

<img src='img/lockboxes.png' width='500'>

For example, you can **encrypt a dataset once for an entire team using a single secret key `T`**, and
**distribute one lockbox per team member containing the secret key**. In each lockbox, the secret key is encrypted
asymmetrically using an ephemeral private key and the member's public key.

To encrypt content using lockboxes, you only need to know the recipients' public keys. You don't need a trusted
side channel to communicate with the recipients, and you never have to transmit the secret in
cleartext. The lockboxes are clearly labeled and can be attached to the encrypted content for
storage, publication, or transmission.

A lockbox is just data: An encrypted payload, plus some metadata.

For example:

```js
const lockbox = {
  // need this to open the lockbox
  encryptionKey: {
    type: 'EPHEMERAL',
    publicKey: 'uwphz8qQaqNbfDx9JhvgOWt9hOgfNR3eZ0sgS1eFUP6QX25Q',
  },

  // information to identify the key that can open this lockbox
  recipient: {
    type: 'USER',
    name: 'alice',
    publicKey: 'x9nX0sBPlbUugyai9BR0A5vuZgMCekWodDpbtty9CrK7u8al',
  },

  // information about the contents of the lockbox
  contents: {
    type: 'ROLE',
    name: 'admin',
    publicKey: 'BmY3ZojiKMQavrPaGc3dp7N1E0nlw6ZtBvqAN4rOIXcWn9ej',
  },

  // the encrypted keyset
  encryptedPayload: 'BxAOzkrxpu2vwL+j98X9VDkcKqDoDQUNM2dJ9dXDsr...2wKeaT0T5wi0JVGh2lbW2VG5==',
}
```

The lockbox contents are encrypted using a single-use, randomly-generated key. The public half of this
ephemeral key is posted publicly on the lockbox; the secret half is used to encrypt the lockbox
contents, and is then discarded.

We use lockboxes to:

- share **team keys** with team **members**
- share **role keys** with **members** in that role
- share **all role keys** with the **admin role**
- share **user keys** with the user's **devices**

### The key graph

Keys provide access to other keys, via lockboxes; so we have an acyclic directed graph where keys are nodes and
lockboxes are edges.

![](img/key-graph.png)

## API

#### `lockbox.create(contents, recipientKeys)`

To make a lockbox, pass in two keysets:

- `contents`, the secret keys to be encrypted in the lockbox. This has to be a `KeysetWithSecrets`.
- `recipientKeys`, the public keys used to open the lockbox. At minimum, this needs to include the recipient's public encryption key (plus metadata for scope and generation).

This makes a lockbox for Alice containing the admin keys.

```js
import * as lockbox from 'lockbox'

const adminLockboxForAlice = lockbox.create(adminKeys, alice.keys)
```

This illustrates the minimum information needed to create a lockbox:

```js
const adminLockboxForAlice = lockbox.create(
  {
    type: 'ROLE',
    name: 'admin',
    generation: 0,
    signature: {
      publicKey: 'B3B8xMFdLDLbd72tXLlgxyvsAJravbATqMtTtje1PQdikGjN=',
      privateKey: 'QI4vBzCKvn6SBvyR7PBKFuuKiSGk3naX0oetx3XUtPK...AX1W0LCdWwMlHhNO3T5jVwnkz=',
    },
    encryption: {
      publicKey: 'asuM3NexDiDs2P2OKQOu3tdXWz2zV6LoaxPfZPLIb8gFIIU0=',
      privateKey: 'e1tcEjpGfKuJz8JObrVJGqq9zrXpNwyHafYEd298p3MyYThJ=',
    },
  },
  {
    type: 'USER',
    name: 'alice',
    generation: 0,
    publicKey: 'JG81tVDDfp3BqXedrtiRiWtvqQKt2175nAceYIPjjMR7z2Y1',
  }
)
```

#### `lockbox.open(lockbox, decryptionKeys)`

To open a lockbox:

```js
const adminKeys = open(adminLockboxForAlice, alice.keys)
```

#### `lockbox.rotate(oldLockbox, contents)`

"Rotating" a lockbox means replacing the keys it contains with new ones.

When a member leaves a team or a role, or a device is lost, we say the corresponding keyset is
'compromised' and we need to replace it -- along with any keys that it provided access to.

For example, if the admin keys are compromised, we'll need to come up with a new set of keys; then
we'll need to find every lockbox that contained the old keys, and replace them with the new ones.

```js
const newAdminKeys = createKeyset({ type: ROLE, name: ADMIN })
const newAdminLockboxForAlice = lockbox.rotate(adminLockboxForAlice, newAdminKeys)
```

We'll also need to so the same for any keys _in lockboxes that the those keys opened_.

![](img/key-rotation.png)

This logic is implemented in the private `rotateKeys` method in the `Team` class.

## `Team`

The `Team` class is the primary API for managing team membership, roles, devices, and encrypted content. It wraps a CRDX store containing the team's signature chain (the "team graph").

### Creating or loading a team

**Creating a new team:**

```js
import { createTeam } from '@localfirst/auth'

const team = createTeam('My Team', context)
```

The founding member is automatically added as an admin.

**Loading an existing team:**

```js
const team = new Team({
  source: savedGraph, // Uint8Array or TeamGraph
  teamKeyring, // Keyring containing team keys
  context, // LocalContext (user, device)
})
```

### Context

The `Team` constructor requires a **context** that identifies the local user:

- **`MemberContext`**: For a team member
  - `user`: UserWithSecrets
  - `device`: DeviceWithSecrets
  - `team`: Team instance
  
- **`ServerContext`**: For a sync server
  - `server`: ServerWithSecrets
  - `team`: Team instance

### Core methods

#### Members

- **`team.members()`**: Returns all members
- **`team.members(userId)`**: Returns a specific member
- **`team.has(userId)`**: Check if a member exists
- **`team.remove(userId)`**: Remove a member (triggers key rotation)
- **`team.memberWasRemoved(userId)`**: Check if member was removed

#### Roles

- **`team.roles()`**: Returns all roles
- **`team.roles(roleName)`**: Returns a specific role
- **`team.hasRole(roleName)`**: Check if a role exists
- **`team.addRole(roleName)`**: Create a new role
- **`team.removeRole(roleName)`**: Remove a role
- **`team.addMemberRole(userId, roleName)`**: Assign a role to a member
- **`team.removeMemberRole(userId, roleName)`**: Remove a role from a member (triggers key rotation)
- **`team.memberHasRole(userId, roleName)`**: Check if a member has a role
- **`team.memberIsAdmin(userId)`**: Check if a member is an admin
- **`team.admins()`**: Returns all admin members
- **`team.membersInRole(roleName)`**: Returns all members with a specific role

#### Devices

- **`team.device(deviceId)`**: Get a device by ID
- **`team.hasDevice(deviceId)`**: Check if a device exists
- **`team.removeDevice(deviceId)`**: Remove a device (triggers key rotation)
- **`team.deviceWasRemoved(deviceId)`**: Check if device was removed
- **`team.memberByDeviceId(deviceId)`**: Find the member who owns a device

#### Invitations

**Inviting a new member:**

```js
const { id, seed } = team.inviteMember({
  expiration: Date.now() + 86400000, // optional: 24 hours
  maxUses: 1, // optional
})
// Share `seed` with the invitee via a trusted channel
```

**Inviting a new device for an existing member:**

```js
const { id, seed } = team.inviteDevice({
  expiration: Date.now() + 1800000, // optional: 30 minutes (default)
})
// Share `seed` with the device (e.g. via QR code)
```

**Managing invitations:**

- **`team.revokeInvitation(id)`**: Revoke an invitation
- **`team.hasInvitation(id)`**: Check if invitation exists
- **`team.getInvitation(id)`**: Get invitation details
- **`team.validateInvitation(proof)`**: Validate a proof of invitation

**Admitting invited members/devices:**

- **`team.admitMember(proof, memberKeys, userName)`**: Admit a new member presenting proof
- **`team.admitDevice(proof, device)`**: Admit a new device presenting proof

**Joining a team (as the invitee):**

```js
team.join(teamKeyring, userKeyring)
```

#### Servers

- **`team.addServer(server)`**: Add a sync server to the team
- **`team.removeServer(host)`**: Remove a server
- **`team.servers()`**: Get all servers
- **`team.servers(host)`**: Get a specific server
- **`team.hasServer(host)`**: Check if server exists
- **`team.serverWasRemoved(host)`**: Check if server was removed

#### Encryption and signatures

**Symmetric encryption for the team or a role:**

```js
// Encrypt for the whole team
const encrypted = team.encrypt(payload)

// Encrypt for a specific role
const encrypted = team.encrypt(payload, 'managers')

// Decrypt
const decrypted = team.decrypt(encrypted)
```

**Sign and verify messages:**

```js
// Sign a message
const signed = team.sign(payload)

// Verify a signed message
const isValid = team.verify(signed)
```

#### Keys

- **`team.keys(scope)`**: Get secret keys for a scope (if available to this device)
- **`team.teamKeys()`**: Get the current team keys
- **`team.teamKeyring()`**: Get all generations of team keys
- **`team.roleKeys(roleName)`**: Get keys for a specific role
- **`team.adminKeys()`**: Get admin role keys
- **`team.userKeyring()`**: Get all generations of the current user's keys
- **`team.changeKeys(newKeys)`**: Rotate the current user's keys

### Graph management

- **`team.graph`**: Access the underlying CRDX graph
- **`team.id`**: The team's unique ID (hash of root)
- **`team.teamName`**: The team's human-readable name
- **`team.save()`**: Serialize the team graph to `Uint8Array`
- **`team.merge(theirGraph)`**: Merge another graph (e.g. from a peer)
- **`team.dispatch(action)`**: Dispatch an action to the graph

### Events

The `Team` class extends `EventEmitter` and emits:

- **`updated`**: Fired when the team graph is modified (locally or via merge)
  ```js
  team.on('updated', ({ head }) => {
    // Save the updated graph
    saveGraph(team.save())
  })
  ```

### Internal architecture

The Team class wraps a **CRDX store**, which maintains:

1. **TeamGraph**: A hash graph (DAG) of signed, encrypted links representing actions
2. **TeamState**: The current state derived by running the graph through a reducer
3. **Reducer**: A pure function that processes each link to compute state
4. **Resolver**: A function that handles concurrent conflicting actions (e.g. two admins concurrently removing each other)

Each action (add member, remove device, etc.) is recorded as a signed link in the graph. The reducer processes these links to compute the current team state, including:

- Members and their roles
- Devices
- Lockboxes containing encrypted keys
- Invitations
- Servers
- Messages

The resolver implements domain-specific conflict resolution rules. For example, if two admins concurrently try to remove each other, the resolver marks both removals as invalid to prevent the team from losing all admins.

## `Connection`

The `Connection` class implements a peer-to-peer authentication and synchronization protocol. It uses an [XState](https://xstate.js.org) state machine to manage the connection lifecycle between two devices.

### Purpose

A `Connection` allows two devices to:

1. **Authenticate** each other using cryptographic proofs
2. **Synchronize** their team graphs
3. **Exchange** encrypted messages
4. **Detect** when peers are removed from the team and disconnect

### Creating a connection

```js
const connection = new Connection({
  // Function to send messages to the peer (you provide this)
  sendMessage: (message: Uint8Array) => {
    // Send via WebSocket, WebRTC, etc.
  },
  
  // Your context (determines how you authenticate)
  context: {
    user,   // UserWithSecrets
    device, // DeviceWithSecrets
    team,   // Team instance
  }
})

// Start the connection
connection.start()

// Feed incoming messages from the peer
peerSocket.on('message', (message: Uint8Array) => {
  connection.receive(message)
})
```

### Context types

The connection behavior depends on your context:

- **`MemberContext`**: You're an existing team member with a device
  - Authenticate using your device ID and keys
  
- **`InviteeMemberContext`**: You're joining as a new member with an invitation
  - Present proof of invitation with your user keys
  
- **`InviteeDeviceContext`**: You're adding a new device for an existing user
  - Present proof of invitation for the device
  
- **`ServerContext`**: You're a sync server
  - Authenticate using server keys

### Connection protocol

The connection goes through several states:

#### 1. Identity claims

Both peers exchange **identity claims** stating who they are:

- **Member device**: "I'm device X belonging to user Y"
- **New member invitee**: "I have an invitation and here are my user keys"
- **New device invitee**: "I have an invitation for a new device"

```text
Alice                           Bob
  |---- CLAIM_IDENTITY -------->|
  |<--- CLAIM_IDENTITY ---------|
```

#### 2. Authentication

Depending on the identity claims, different authentication flows occur:

**For invitations:**

If one peer presents an invitation, the member peer validates the proof:

```text
New Member                    Existing Member
  |---- CLAIM_IDENTITY -------->|
  | (includes invitation proof) |
  |                              | (validates invitation)
  |<--- ACCEPT_INVITATION ------|
  |    (includes team graph)    |
```

**For existing members:**

Both peers challenge each other with a signature challenge:

```text
Alice                           Bob
  |--- CHALLENGE_IDENTITY ----->|
  |                              | (signs challenge)
  |<---- PROVE_IDENTITY ---------|
  | (verifies signature)         |
  |---- ACCEPT_IDENTITY -------->|
  |                              |
  |<-- CHALLENGE_IDENTITY -------|
  | (signs challenge)            |
  |---- PROVE_IDENTITY --------->|
  |                              | (verifies signature)
  |<--- ACCEPT_IDENTITY ---------|
```

The challenge includes:

- A random nonce
- A timestamp
- The device's scope (type and name)

The peer signs this challenge with their device's signature key.

#### 3. Session key negotiation

Once authenticated, both peers negotiate a shared **session key** for encrypting subsequent messages:

1. Each peer generates a random seed
2. Each peer encrypts their seed using asymmetric encryption (their private key + peer's public key)
3. Both peers exchange seeds
4. Both peers derive the same shared key by combining both seeds

```text
Alice                           Bob
  |------ SEED (encrypted) ---->|
  |<----- SEED (encrypted) -----|
  |                              |
  | Both derive shared key       |
```

This establishes an encrypted channel for all further communication.

#### 4. Synchronization

Once the session key is established, peers synchronize their team graphs using the CRDX sync protocol:

```text
Alice                           Bob
  |------- SYNC message ------->|
  |<------ SYNC message ---------|
  |------- SYNC message ------->|
  |         (repeat until        |
  |        graphs are equal)     |
```

The sync protocol exchanges links that one peer has but the other doesn't, until both graphs are identical.

#### 5. Connected

Once synchronized, the connection enters the **connected** state. In this state:

- Peers continue to exchange sync messages when the graph is updated locally
- Peers can exchange encrypted messages
- The connection monitors for peer removal (member/device/server removed from team)
- If a peer is removed, the connection automatically disconnects

```text
Alice                           Bob
  |                              |
  | (Alice adds a new member)    |
  |------- SYNC message ------->|
  | (Bob merges the update)      |
  |                              |
  | <------ SYNC message --------|
  |                              |
  | (Bob removes Alice's device) |
  |<------ SYNC message ---------|
  | (Alice merges, detects       |
  |  removal, disconnects)       |
  X                              |
```

### Events

The `Connection` class extends `EventEmitter` and emits:

- **`change`**: State machine transitions

  ```js
  connection.on('change', (state) => {
    console.log('Connection state:', state)
  })
  ```

- **`connected`**: Successfully connected and authenticated

  ```js
  connection.on('connected', () => {
    console.log('Connected to peer!')
  })
  ```

- **`joined`**: Successfully joined a team via invitation

  ```js
  connection.on('joined', ({ team, user, teamKeyring }) => {
    // Save the team and user info
    saveTeam(team.save())
    saveUser(user)
  })
  ```

- **`updated`**: Team graph was updated by peer

  ```js
  connection.on('updated', () => {
    // Save the updated team graph
    saveTeam(team.save())
  })
  ```

- **`message`**: Received an encrypted message from peer

  ```js
  connection.on('message', (message) => {
    console.log('Received:', message)
  })
  ```

- **`localError`**: We detected an error (e.g. invalid invitation)

  ```js
  connection.on('localError', (error) => {
    console.error('Local error:', error)
  })
  ```

- **`remoteError`**: Peer detected an error and reported it

  ```js
  connection.on('remoteError', (error) => {
    console.error('Remote error:', error)
  })
  ```

- **`disconnected`**: Connection terminated

  ```js
  connection.on('disconnected', () => {
    console.log('Disconnected')
  })
  ```

### Methods

- **`connection.start()`**: Start the connection state machine
- **`connection.receive(message: Uint8Array)`**: Process an incoming message from the peer
- **`connection.send(message: unknown)`**: Send an encrypted message to the peer (when connected)
- **`connection.disconnectAndStop()`**: Gracefully disconnect
- **`connection.state`**: Current state of the connection (XState snapshot)

### Error handling

The connection automatically disconnects on errors:

- **`INVITATION_PROOF_INVALID`**: Invalid invitation proof
- **`IDENTITY_PROOF_INVALID`**: Failed signature challenge
- **`DEVICE_UNKNOWN`**: Device not found in team
- **`DEVICE_REMOVED`**: Device was removed from team
- **`MEMBER_REMOVED`**: Member was removed from team
- **`SERVER_REMOVED`**: Server was removed from team
- **`JOINED_WRONG_TEAM`**: Invitee tried to join a different team
- **`NEITHER_IS_MEMBER`**: Both peers presented invitations (impossible)
- **`TIMEOUT`**: Operation took too long (7 seconds)
- **`ENCRYPTION_FAILURE`**: Failed to decrypt a message

When an error occurs, the connection sends an error message to the peer and transitions to the **disconnected** state.

### Security considerations

- **Device-level authentication**: Devices authenticate independently using their own keys, not user keys
- **Signature challenge**: Proves possession of private signature key
- **Session key**: Provides forward secrecy for message encryption
- **No replay attacks**: Session keys are derived from random seeds, fresh per connection
- **Automatic removal detection**: Connections automatically terminate when peers are removed from the team
- **Timeout protection**: All protocol steps have timeouts to prevent hanging connections

### State machine visualization

The connection state machine can be visualized using the [Stately visualizer](https://stately.ai/registry/editor/69889811-5f81-4d58-8ef1-f6f3d99fb9ee?machineId=989039f7-631c-4021-a9da-d5f6912dcb03).

The main states are:

```text
awaitingIdentityClaim
    ↓
authenticating
    ├── checkingInvitations
    ├── awaitingInvitationAcceptance
    ├── validatingInvitation
    └── checkingIdentity (parallel)
        ├── provingMyIdentity
        └── verifyingTheirIdentity
    ↓
negotiating (session key)
    ↓
synchronizing (team graph)
    ↓
connected
    ↓
disconnected
```

### Network agnostic

The `Connection` class is **network-agnostic**. It doesn't care about the underlying transport:

- WebSocket
- WebRTC
- HTTP polling
- Bluetooth
- Custom protocol

You provide the `sendMessage` function, and call `connection.receive()` when messages arrive. The connection handles all authentication, encryption, and synchronization logic.
