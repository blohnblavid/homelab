const http = require('http');
const fs = require('fs');
const path = require('path');
const DATA_FILE = '/data/state.json';
const HTML_FILE = path.join(__dirname, 'index.html');
function loadState() {
  try { return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); }
  catch(e) { return {}; }
}
function saveState(state) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(state), 'utf8');
}
const server = http.createServer((req, res) => {
  if (req.method === 'GET' && req.url === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(fs.readFileSync(HTML_FILE));
    return;
  }
  if (req.method === 'GET' && req.url === '/state') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(loadState()));
    return;
  }
  if (req.method === 'POST' && req.url === '/state') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        saveState(JSON.parse(body));
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"ok":true}');
      } catch(e) {
        res.writeHead(400);
        res.end('bad request');
      }
    });
    return;
  }
  res.writeHead(404);
  res.end('not found');
});
server.listen(3050, () => console.log('enchants running on :3050'));
