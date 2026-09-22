const root = document.getElementById('root')

async function refreshThreats() {
  if (window.cybershield && window.cybershield.getThreats) {
    const threats = await window.cybershield.getThreats()
    renderThreats(threats)
  } else {
    root.innerHTML = '<h3>CyberShield Desktop</h3><p>No security engine available (placeholder).</p>'
  }
}

function renderThreats(threats) {
  if (!threats || threats.length === 0) {
    root.innerHTML = '<h3>CyberShield Desktop</h3><p>No threats detected.</p>'
    return
  }
  const list = document.createElement('ul')
  threats.forEach(t => {
    const li = document.createElement('li')
    li.textContent = `${t.threatType} - ${t.appName || t.appPackage} [${t.severity}]`
    list.appendChild(li)
  })
  root.innerHTML = '<h3>Threats</h3>'
  root.appendChild(list)
}

refreshThreats()
setInterval(refreshThreats, 10000)
