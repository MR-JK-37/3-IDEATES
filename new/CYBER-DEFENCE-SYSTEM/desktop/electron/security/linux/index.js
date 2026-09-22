// Linux security engine with optional Rust socket integration
const fs = require('fs')
const net = require('net')
const path = require('path')

const SOCKET_PATH = process.env.CYBERSHIELD_SOCKET || '/tmp/cybershield.sock'

let connected = false
let recentEvents = []

function tryConnectSocket() {
  if (connected) return
  if (!fs.existsSync(SOCKET_PATH)) return

  const client = net.createConnection({ path: SOCKET_PATH }, () => {
    console.log('Connected to CyberShield unix socket', SOCKET_PATH)
    connected = true
  })

  let buffer = ''
  client.on('data', (chunk) => {
    buffer += chunk.toString('utf8')
    let idx
    while ((idx = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, idx).trim()
      buffer = buffer.slice(idx + 1)
      if (!line) continue
      try {
        const obj = JSON.parse(line)
        recentEvents.unshift(obj)
        if (recentEvents.length > 500) recentEvents.pop()
      } catch (e) {
        console.warn('Failed to parse event JSON', e)
      }
    }
  })

  client.on('end', () => {
    console.log('Socket connection ended')
    connected = false
  })

  client.on('error', (err) => {
    console.warn('Socket client error', err.message)
    connected = false
    client.destroy()
  })
}

// Try to connect periodically
setInterval(tryConnectSocket, 2000)
tryConnectSocket()

module.exports = {
  start: () => console.log('Linux security engine started (socket client) - socket:', SOCKET_PATH),
  getRecentThreats: async () => {
    return recentEvents.slice(0, 100)
  },
  scanFile: async (filePath) => {
    // If Rust engine present and connected it should be streaming events; fallback to local JS entropy check
    try {
      const buf = fs.readFileSync(filePath)
      const freq = new Array(256).fill(0)
      for (let i = 0; i < buf.length; i++) freq[buf[i]]++
      let entropy = 0
      for (let c of freq) {
        if (c === 0) continue
        const p = c / buf.length
        entropy -= p * Math.log2(p)
      }
      return { entropy }
    } catch (e) {
      return { error: e.message }
    }
  }
}
