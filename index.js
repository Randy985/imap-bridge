const crypto = require('crypto');
const express = require('express');
const { ImapFlow } = require('imapflow');
const { simpleParser } = require('mailparser');

const app = express();

app.use(express.json({ limit: '50mb' }));

const PORT = Number(process.env.PORT || 3000);
const SECRET_TOKEN = process.env.SECRET_TOKEN;

function safeTokenEquals(receivedToken, expectedToken) {
  if (!receivedToken || !expectedToken) {
    return false;
  }

  const received = Buffer.from(String(receivedToken));
  const expected = Buffer.from(String(expectedToken));

  if (received.length !== expected.length) {
    return false;
  }

  return crypto.timingSafeEqual(received, expected);
}

function authToken(req, res, next) {
  if (!SECRET_TOKEN) {
    return res.status(500).json({
      success: false,
      error: 'SECRET_TOKEN no configurado'
    });
  }

  const authorization = String(req.headers.authorization || '');

  const bearerToken = authorization.startsWith('Bearer ')
    ? authorization.slice(7).trim()
    : '';

  const token = String(req.headers.token || bearerToken || '');

  if (!safeTokenEquals(token, SECRET_TOKEN)) {
    return res.status(401).json({
      success: false,
      error: 'No autorizado'
    });
  }

  next();
}

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
    socketTimeout: 20_000
  });
}

function forceCloseClient(client) {
  if (!client) {
    return;
  }

  try {
    client.close();
  } catch (_) {
    // Ignorar errores de cierre forzado.
  }
}

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
        }, 2_000);
      })
    ]);
  } catch (_) {
    forceCloseClient(client);
  }
}

async function runWithTimeout(operation, timeoutMs, onTimeout) {
  let timeoutId;

  try {
    return await Promise.race([
      operation(),
      new Promise((_, reject) => {
        timeoutId = setTimeout(() => {
          try {
            onTimeout?.();
          } catch (_) {
            // Ignorar errores durante cancelación.
          }

          reject(new Error(`Tiempo máximo excedido (${timeoutMs} ms)`));
        }, timeoutMs);
      })
    ]);
  } finally {
    if (timeoutId) {
      clearTimeout(timeoutId);
    }
  }
}

async function searchUnreadUids(config, limit) {
  let client;
  let lock;

  try {
    client = createClient(config);

    await runWithTimeout(
      () => client.connect(),
      12_000,
      () => forceCloseClient(client)
    );

    lock = await runWithTimeout(
      () => client.getMailboxLock(config.mailbox),
      10_000,
      () => forceCloseClient(client)
    );

    const uids = await runWithTimeout(
      () => client.search({ seen: false }, { uid: true }),
      15_000,
      () => forceCloseClient(client)
    );

    const unreadUids = Array.isArray(uids) ? uids : [];

    return unreadUids
      .slice(-limit)
      .reverse();
  } finally {
    if (lock) {
      try {
        lock.release();
      } catch (_) {
        // Ignorar errores de liberación.
      }
    }

    await closeClient(client);
  }
}

async function fetchMessageByUid(config, uid) {
  let client;
  let lock;

  try {
    client = createClient(config);

    await runWithTimeout(
      () => client.connect(),
      12_000,
      () => forceCloseClient(client)
    );

    lock = await runWithTimeout(
      () => client.getMailboxLock(config.mailbox),
      10_000,
      () => forceCloseClient(client)
    );

    const message = await runWithTimeout(
      () =>
        client.fetchOne(
          uid,
          {
            source: true,
            envelope: true,
            internalDate: true
          },
          {
            uid: true
          }
        ),
      20_000,
      () => forceCloseClient(client)
    );

    if (!message?.source) {
      throw new Error('Correo sin contenido');
    }

    const parsed = await runWithTimeout(
      () => simpleParser(message.source),
      15_000,
      () => forceCloseClient(client)
    );

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

    return {
      uid: message.uid || uid,
      internalDate: message.internalDate || null,
      messageId: parsed.messageId || null,
      from: parsed.from?.text || '',
      to: parsed.to?.text || '',
      subject: parsed.subject || '',
      text: parsed.text || '',
      html: parsed.html || '',
      attachments
    };
  } finally {
    if (lock) {
      try {
        lock.release();
      } catch (_) {
        // Ignorar errores de liberación.
      }
    }

    await closeClient(client);
  }
}

app.get('/api/health', (req, res) => {
  return res.json({
    status: 'ok',
    mode: 'multi-account',
    token_configured: Boolean(SECRET_TOKEN),
    timestamp: new Date().toISOString()
  });
});

app.post('/api/test', authToken, async (req, res) => {
  let client;

  try {
    const config = getImapConfig(req.body);

    client = createClient(config);

    await runWithTimeout(
      () => client.connect(),
      12_000,
      () => forceCloseClient(client)
    );

    const status = await runWithTimeout(
      () =>
        client.status(config.mailbox, {
          messages: true,
          unseen: true
        }),
      12_000,
      () => forceCloseClient(client)
    );

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

    forceCloseClient(client);

    return res.status(500).json({
      success: false,
      error: error.message,
      code: error.code || null,
      responseCode: error.responseCode || null
    });
  }
});

app.post('/api/inbox', authToken, async (req, res) => {
  try {
    const config = getImapConfig(req.body);

    const requestedLimit = Number.parseInt(
      String(req.body.limit || '10'),
      10
    );

    const limit = Number.isInteger(requestedLimit)
      ? Math.min(Math.max(requestedLimit, 1), 10)
      : 10;

    const selectedUids = await searchUnreadUids(config, limit);

    const messages = [];
    const failed = [];

    for (const uid of selectedUids) {
      try {
        const message = await fetchMessageByUid(config, uid);
        messages.push(message);
      } catch (error) {
        console.error('IMAP message failed:', {
          uid,
          message: error.message
        });

        failed.push({
          uid,
          error: error.message
        });
      }
    }

    return res.json({
      success: true,
      count: messages.length,
      failed_count: failed.length,
      failed,
      messages
    });
  } catch (error) {
    console.error('IMAP inbox failed:', {
      message: error.message,
      code: error.code || null,
      responseCode: error.responseCode || null
    });

    return res.status(500).json({
      success: false,
      error: error.message,
      code: error.code || null,
      responseCode: error.responseCode || null
    });
  }
});

app.post('/api/mark-read', authToken, async (req, res) => {
  let client;
  let lock;

  try {
    const config = getImapConfig(req.body);

    const uid = Number.parseInt(
      String(req.body.uid || ''),
      10
    );

    if (!Number.isInteger(uid) || uid <= 0) {
      return res.status(400).json({
        success: false,
        error: 'uid requerido'
      });
    }

    client = createClient(config);

    await runWithTimeout(
      () => client.connect(),
      12_000,
      () => forceCloseClient(client)
    );

    lock = await runWithTimeout(
      () => client.getMailboxLock(config.mailbox),
      10_000,
      () => forceCloseClient(client)
    );

    await runWithTimeout(
      () =>
        client.messageFlagsAdd(
          uid,
          ['\\Seen'],
          {
            uid: true
          }
        ),
      10_000,
      () => forceCloseClient(client)
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

    forceCloseClient(client);

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