const crypto = require('crypto');
const express = require('express');
const { ImapFlow } = require('imapflow');
const { simpleParser } = require('mailparser');

const app = express();

app.use(express.json({ limit: '50mb' }));

const PORT = Number(process.env.PORT || 3000);
const SECRET_TOKEN = process.env.SECRET_TOKEN;

/**
 * Compara tokens de forma segura.
 */
function safeTokenEquals(receivedToken, expectedToken) {
  if (!receivedToken || !expectedToken) {
    return false;
  }

  const received = Buffer.from(receivedToken);
  const expected = Buffer.from(expectedToken);

  if (received.length !== expected.length) {
    return false;
  }

  return crypto.timingSafeEqual(received, expected);
}

/**
 * Protege los endpoints privados.
 */
function authToken(req, res, next) {
  if (!SECRET_TOKEN) {
    return res.status(500).json({
      success: false,
      error: 'SECRET_TOKEN no configurado'
    });
  }

  const authorization = req.headers.authorization || '';

  const bearerToken = authorization.startsWith('Bearer ')
    ? authorization.slice(7).trim()
    : null;

  const token = req.headers.token || bearerToken;

  if (!safeTokenEquals(token, SECRET_TOKEN)) {
    return res.status(401).json({
      success: false,
      error: 'No autorizado'
    });
  }

  next();
}

/**
 * Obtiene la configuración IMAP enviada por Base44.
 */
function getImapConfig(body = {}) {
  const imap = body.imap || {};

  const host = String(imap.host || '').trim();
  const port = Number(imap.port || 993);
  const user = String(imap.user || '').trim();
  const pass = String(imap.pass || '');
  const mailbox = String(imap.mailbox || 'INBOX').trim();

  if (!host) {
    throw new Error('imap.host requerido');
  }

  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('imap.port inválido');
  }

  if (!user) {
    throw new Error('imap.user requerido');
  }

  if (!pass) {
    throw new Error('imap.pass requerido');
  }

  if (!mailbox) {
    throw new Error('imap.mailbox inválido');
  }

  return {
    host,
    port,
    user,
    pass,
    mailbox
  };
}

/**
 * Crea una conexión IMAP independiente por solicitud.
 */
function createClient(config) {
  return new ImapFlow({
    host: config.host,
    port: config.port,
    secure: config.port === 993,
    auth: {
      user: config.user,
      pass: config.pass
    },
    logger: false,
    connectionTimeout: 10_000,
    greetingTimeout: 10_000,
    socketTimeout: 30_000
  });
}

/**
 * Cierra la conexión sin bloquear indefinidamente.
 */
async function closeClient(client) {
  if (!client) {
    return;
  }

  try {
    await Promise.race([
      client.logout(),
      new Promise((_, reject) => {
        setTimeout(() => {
          reject(new Error('IMAP logout timeout'));
        }, 3_000);
      })
    ]);
  } catch (_) {
    try {
      client.close();
    } catch (_) {
      // Ignorar errores de cierre.
    }
  }
}

/**
 * Verifica que el servicio esté activo.
 */
app.get('/api/health', (req, res) => {
  return res.json({
    status: 'ok',
    mode: 'multi-account',
    token_configured: Boolean(SECRET_TOKEN),
    timestamp: new Date().toISOString()
  });
});

/**
 * Verifica la conexión de una cuenta IMAP.
 */
app.post('/api/test', authToken, async (req, res) => {
  let client;

  try {
    const config = getImapConfig(req.body);

    client = createClient(config);

    await client.connect();

    const status = await client.status(config.mailbox, {
      messages: true,
      unseen: true
    });

    await closeClient(client);
    client = null;

    return res.json({
      success: true,
      message: 'Conexion IMAP exitosa',
      mailbox: config.mailbox,
      total_messages: status.messages,
      unseen: status.unseen
    });
  } catch (error) {
    console.error('IMAP test failed:', {
      message: error.message,
      code: error.code || null,
      responseCode: error.responseCode || null
    });

    await closeClient(client);

    return res.status(500).json({
      success: false,
      error: error.message,
      code: error.code || null,
      responseCode: error.responseCode || null
    });
  }
});

/**
 * Lee correos no leídos de una cuenta.
 */
app.post('/api/inbox', authToken, async (req, res) => {
  let client;
  let lock;

  try {
    const config = getImapConfig(req.body);

    const requestedLimit = Number.parseInt(
      String(req.body.limit || '50'),
      10
    );

    const limit = Number.isInteger(requestedLimit)
      ? Math.min(Math.max(requestedLimit, 1), 200)
      : 50;

    client = createClient(config);

    await client.connect();

    lock = await client.getMailboxLock(config.mailbox);

    const messages = [];

    for await (
      const message of client.fetch(
        {
          seen: false
        },
        {
          source: true,
          envelope: true,
          internalDate: true
        },
        {
          uid: true
        }
      )
    ) {
      const parsed = await simpleParser(message.source);

      const attachments = (parsed.attachments || []).map((attachment) => ({
        filename: attachment.filename || null,
        contentType:
          attachment.contentType || 'application/octet-stream',
        size:
          attachment.size ||
          attachment.content?.length ||
          0,
        content_base64: attachment.content
          ? attachment.content.toString('base64')
          : ''
      }));

      messages.push({
        uid: message.uid,
        internalDate: message.internalDate,
        messageId: parsed.messageId || null,
        from: parsed.from?.text || '',
        to: parsed.to?.text || '',
        subject: parsed.subject || '',
        text: parsed.text || '',
        html: parsed.html || '',
        attachments
      });

      if (messages.length >= limit) {
        break;
      }
    }

    lock.release();
    lock = null;

    await closeClient(client);
    client = null;

    return res.json({
      success: true,
      count: messages.length,
      messages
    });
  } catch (error) {
    console.error('IMAP inbox failed:', {
      message: error.message,
      code: error.code || null,
      responseCode: error.responseCode || null
    });

    if (lock) {
      try {
        lock.release();
      } catch (_) {
        // Ignorar errores de liberación.
      }
    }

    await closeClient(client);

    return res.status(500).json({
      success: false,
      error: error.message,
      code: error.code || null,
      responseCode: error.responseCode || null
    });
  }
});

/**
 * Marca un correo como leído.
 */
app.post('/api/mark-read', authToken, async (req, res) => {
  let client;
  let lock;

  try {
    const config = getImapConfig(req.body);

    const uid = Number.parseInt(String(req.body.uid || ''), 10);

    if (!Number.isInteger(uid) || uid <= 0) {
      return res.status(400).json({
        success: false,
        error: 'uid requerido'
      });
    }

    client = createClient(config);

    await client.connect();

    lock = await client.getMailboxLock(config.mailbox);

    await client.messageFlagsAdd(
      uid,
      ['\\Seen'],
      {
        uid: true
      }
    );

    lock.release();
    lock = null;

    await closeClient(client);
    client = null;

    return res.json({
      success: true,
      message: `UID ${uid} marcado como leido`
    });
  } catch (error) {
    console.error('IMAP mark-read failed:', {
      message: error.message,
      code: error.code || null,
      responseCode: error.responseCode || null
    });

    if (lock) {
      try {
        lock.release();
      } catch (_) {
        // Ignorar errores de liberación.
      }
    }

    await closeClient(client);

    return res.status(500).json({
      success: false,
      error: error.message,
      code: error.code || null,
      responseCode: error.responseCode || null
    });
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(
    `IMAP Bridge multi-account escuchando en puerto ${PORT}`
  );

  console.log(
    `Token: ${SECRET_TOKEN ? 'configurado' : 'NO configurado'}`
  );
});