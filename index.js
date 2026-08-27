const crypto = require('crypto');
const express = require('express');
const { ImapFlow } = require('imapflow');
const { simpleParser } = require('mailparser');

const app = express();

app.use(express.json({ limit: '50mb' }));

const PORT = Number(process.env.PORT || 3000);
const SECRET_TOKEN = process.env.SECRET_TOKEN;

const DEFAULT_BATCH_SIZE = 20;
const MAX_BATCH_SIZE = 50;

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
    connectionTimeout: 15_000,
    greetingTimeout: 15_000,
    socketTimeout: 60_000
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
        }, 3_000);
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

          reject(
            new Error(`Tiempo máximo excedido (${timeoutMs} ms)`)
          );
        }, timeoutMs);
      })
    ]);
  } finally {
    if (timeoutId) {
      clearTimeout(timeoutId);
    }
  }
}

function parseIsoDate(value, fieldName) {
  if (!value) {
    return null;
  }

  const normalized = String(value).trim();

  if (!/^\d{4}-\d{2}-\d{2}$/.test(normalized)) {
    throw new Error(`${fieldName} debe usar formato YYYY-MM-DD`);
  }

  const date = new Date(`${normalized}T00:00:00.000Z`);

  if (Number.isNaN(date.getTime())) {
    throw new Error(`${fieldName} inválido`);
  }

  return normalized;
}

function addUtcDays(dateString, days) {
  const [year, month, day] = dateString
    .split('-')
    .map(Number);

  const date = new Date(
    Date.UTC(year, month - 1, day + days)
  );

  return date.toISOString().slice(0, 10);
}

function parseBatchSize(value) {
  const parsed = Number.parseInt(
    String(value || DEFAULT_BATCH_SIZE),
    10
  );

  if (!Number.isInteger(parsed)) {
    return DEFAULT_BATCH_SIZE;
  }

  return Math.min(
    Math.max(parsed, 1),
    MAX_BATCH_SIZE
  );
}

function parseCursor(value) {
  if (
    value === undefined ||
    value === null ||
    value === ''
  ) {
    return null;
  }

  const parsed = Number.parseInt(String(value), 10);

  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error('cursor inválido');
  }

  return parsed;
}

function buildSearchCriteria({
  includeRead,
  dateFrom,
  dateTo,
  cursor
}) {
  const criteria = {};

  if (!includeRead) {
    criteria.seen = false;
  }

  if (dateFrom) {
    criteria.since = dateFrom;
  }

  if (dateTo) {
    criteria.before = addUtcDays(dateTo, 1);
  }

  if (cursor) {
    criteria.uid = `1:${cursor - 1}`;
  }

  return criteria;
}

async function parseFetchedMessage(message) {
  if (!message?.source) {
    throw new Error('Correo sin contenido');
  }

  const parsed = await simpleParser(message.source);

  const attachments = (parsed.attachments || []).map(
    (attachment) => ({
      filename: attachment.filename || null,
      contentType:
        attachment.contentType ||
        'application/octet-stream',
      size:
        attachment.size ||
        attachment.content?.length ||
        0,
      content_base64: attachment.content
        ? attachment.content.toString('base64')
        : ''
    })
  );

  return {
    uid: message.uid,
    internalDate: message.internalDate || null,
    messageId: parsed.messageId || null,
    from: parsed.from?.text || '',
    to: parsed.to?.text || '',
    subject: parsed.subject || '',
    text: parsed.text || '',
    html: parsed.html || '',
    attachments
  };
}

async function fetchInboxBatch(config, options = {}) {
  const {
    includeRead = false,
    dateFrom = null,
    dateTo = null,
    batchSize = DEFAULT_BATCH_SIZE,
    cursor = null
  } = options;

  let client;
  let lock;

  try {
    client = createClient(config);

    await runWithTimeout(
      () => client.connect(),
      15_000,
      () => forceCloseClient(client)
    );

    lock = await runWithTimeout(
      () => client.getMailboxLock(config.mailbox),
      15_000,
      () => forceCloseClient(client)
    );

    const searchCriteria = buildSearchCriteria({
      includeRead,
      dateFrom,
      dateTo,
      cursor
    });

    const uids = await runWithTimeout(
      () =>
        client.search(
          searchCriteria,
          { uid: true }
        ),
      20_000,
      () => forceCloseClient(client)
    );

    const matchingUids = Array.isArray(uids)
      ? uids
      : [];

    if (matchingUids.length === 0) {
      return {
        messages: [],
        failed: [],
        hasMore: false,
        nextCursor: null,
        totalMatching: 0
      };
    }

    matchingUids.sort((a, b) => b - a);

    const selectedUids = matchingUids.slice(
      0,
      batchSize
    );

    const hasMore =
      matchingUids.length > selectedUids.length;

    const nextCursor = hasMore
      ? selectedUids[selectedUids.length - 1]
      : null;

    const fetched = await runWithTimeout(
      () =>
        client.fetchAll(
          selectedUids,
          {
            uid: true,
            source: true,
            envelope: true,
            internalDate: true
          },
          {
            uid: true
          }
        ),
      60_000,
      () => forceCloseClient(client)
    );

    const fetchedByUid = new Map();

    for (const message of fetched || []) {
      fetchedByUid.set(message.uid, message);
    }

    const messages = [];
    const failed = [];

    for (const uid of selectedUids) {
      const rawMessage = fetchedByUid.get(uid);

      if (!rawMessage) {
        failed.push({
          uid,
          error: 'Correo no devuelto por IMAP'
        });

        continue;
      }

      try {
        const parsedMessage =
          await parseFetchedMessage(rawMessage);

        messages.push(parsedMessage);
      } catch (error) {
        console.error('IMAP parse failed:', {
          uid,
          message: error.message
        });

        failed.push({
          uid,
          error: error.message
        });
      }
    }

    return {
      messages,
      failed,
      hasMore,
      nextCursor,
      totalMatching: matchingUids.length
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
    mode: 'multi-account-batched',
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
      15_000,
      () => forceCloseClient(client)
    );

    const status = await runWithTimeout(
      () =>
        client.status(config.mailbox, {
          messages: true,
          unseen: true
        }),
      15_000,
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

    const includeRead =
      req.body.include_read === true;

    const dateFrom = parseIsoDate(
      req.body.date_from,
      'date_from'
    );

    const dateTo = parseIsoDate(
      req.body.date_to,
      'date_to'
    );

    if (dateFrom && dateTo && dateFrom > dateTo) {
      return res.status(400).json({
        success: false,
        error:
          'date_from no puede ser mayor que date_to'
      });
    }

    const batchSize = parseBatchSize(
      req.body.batch_size
    );

    const cursor = parseCursor(
      req.body.cursor
    );

    const result = await fetchInboxBatch(
      config,
      {
        includeRead,
        dateFrom,
        dateTo,
        batchSize,
        cursor
      }
    );

    return res.json({
      success: true,

      count: result.messages.length,

      failed_count: result.failed.length,

      failed: result.failed,

      messages: result.messages,

      pagination: {
        batch_size: batchSize,
        has_more: result.hasMore,
        next_cursor: result.nextCursor
      },

      search: {
        include_read: includeRead,
        date_from: dateFrom,
        date_to: dateTo,
        matching_remaining_in_search:
          result.totalMatching
      }
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
      15_000,
      () => forceCloseClient(client)
    );

    lock = await runWithTimeout(
      () =>
        client.getMailboxLock(
          config.mailbox
        ),
      15_000,
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
      15_000,
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
    `Token: ${
      SECRET_TOKEN
        ? 'configurado'
        : 'NO configurado'
    }`
  );
});