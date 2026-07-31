const express = require('express');
const { ImapFlow } = require('imapflow');
const { simpleParser } = require('mailparser');
const app = express();

app.use(express.json({ limit: '50mb' }));

const PORT = process.env.PORT || 3000;
const IMAP_HOST = process.env.IMAP_HOST;
const IMAP_PORT = parseInt(process.env.IMAP_PORT || '993', 10);
const IMAP_USER = process.env.IMAP_USER;
const IMAP_PASS = process.env.IMAP_PASS;
const IMAP_MAILBOX = process.env.IMAP_MAILBOX || 'INBOX';
const SECRET_TOKEN = process.env.SECRET_TOKEN;

function authToken(req, res, next) {
  const token = req.headers['token'] || req.headers['authorization']?.replace('Bearer ', '');
  if (!SECRET_TOKEN) return res.status(500).json({ error: 'SECRET_TOKEN no configurado' });
  if (token !== SECRET_TOKEN) return res.status(401).json({ error: 'No autorizado' });
  next();
}

function createClient(override) {
  const host = override?.imap_host || IMAP_HOST;
  const port = override?.imap_port ? parseInt(override.imap_port, 10) : IMAP_PORT;
  const user = override?.imap_user || IMAP_USER;
  const pass = override?.imap_pass || IMAP_PASS;
  if (!host || !user || !pass) throw new Error('Faltan credenciales IMAP');
  return new ImapFlow({ host, port, secure: port === 993, auth: { user, pass }, logger: false });
}

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', imap_host: IMAP_HOST ? 'configurado' : 'falta', token: SECRET_TOKEN ? 'configurado' : 'falta', timestamp: new Date().toISOString() });
});

app.post('/api/test', authToken, async (req, res) => {
  let client;
  try {
    client = createClient(req.body);
    await client.connect();
    const lock = await client.getMailboxLock(IMAP_MAILBOX);
    let status;
    try { status = await client.status(IMAP_MAILBOX, { messages: true, unseen: true }); } finally { lock.release(); }
    await client.logout();
    res.json({ success: true, message: 'Conexion IMAP exitosa', mailbox: IMAP_MAILBOX, total_messages: status.messages, unseen: status.unseen });
  } catch (err) {
    if (client) try { await client.logout(); } catch (e) {}
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/inbox', authToken, async (req, res) => {
  let client;
  try {
    client = createClient(req.body);
    await client.connect();
    const lock = await client.getMailboxLock(IMAP_MAILBOX);
    let messages = [];
    try {
      const limit = Math.min(parseInt(req.body?.limit || '50', 10), 200);
      for await (let msg of client.fetch({ seen: false }, { source: true, envelope: true, internalDate: true }, { uid: true })) {
        const parsed = await simpleParser(msg.source);
        const attachments = [];
        if (parsed.attachments && parsed.attachments.length > 0) {
          for (const att of parsed.attachments) {
            attachments.push({ filename: att.filename, contentType: att.contentType, size: att.size, content_base64: att.content.toString('base64') });
          }
        }
        messages.push({ uid: msg.uid, internalDate: msg.internalDate, messageId: parsed.messageId, from: parsed.from?.text || '', to: parsed.to?.text || '', subject: parsed.subject || '', text: parsed.text || '', html: parsed.html || '', attachments });
        if (messages.length >= limit) break;
      }
    } finally { lock.release(); }
    await client.logout();
    res.json({ success: true, count: messages.length, messages });
  } catch (err) {
    if (client) try { await client.logout(); } catch (e) {}
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/mark-read', authToken, async (req, res) => {
  let client;
  try {
    const uid = parseInt(req.body?.uid, 10);
    if (!uid) return res.status(400).json({ error: 'uid requerido' });
    client = createClient(req.body);
    await client.connect();
    const lock = await client.getMailboxLock(IMAP_MAILBOX);
    try { await client.messageFlagsAdd(uid, ['\\Seen'], { uid: true }); } finally { lock.release(); }
    await client.logout();
    res.json({ success: true, message: `UID ${uid} marcado como leido` });
  } catch (err) {
    if (client) try { await client.logout(); } catch (e) {}
    res.status(500).json({ success: false, error: err.message });
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`IMAP Bridge escuchando en puerto ${PORT}`);
  console.log(`IMAP: ${IMAP_USER}@${IMAP_HOST}:${IMAP_PORT} [${IMAP_MAILBOX}]`);
  console.log(`Token: ${SECRET_TOKEN ? 'configurado' : 'NO configurado'}`);
});