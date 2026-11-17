const crypto = require('crypto');
const express = require('express');
const { ImapFlow } = require('imapflow');
const { simpleParser } = require('mailparser');

const app = express();

app.use(express.json({ limit: '50mb' }));

const PORT = Number(process.env.PORT || 3000);
const SECRET_TOKEN = process.env.SECRET_TOKEN;

// Estos límites controlan el tamaño de página y cada consulta por lotes.
const DEFAULT_BATCH_SIZE = 20;
const MAX_BATCH_SIZE = 20;

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

async function closeClient(client, diagnostics = null) {
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
  } catch (error) {
    diagnostics?.error('cleanup_error', error, { stage: 'imap_logout' });
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

function buildSearchCriteria({ cursor }) {
  const criteria = { all: true };

  if (cursor > 1) {
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

function createInboxDiagnostics() {
  const requestId = crypto.randomUUID();
  const startedAt = process.hrtime.bigint();
  const diagnostics = {
    stage: 'request',
    failureStage: null,
    log(event, details = {}, isError = false) {
      const memory = process.memoryUsage();
      const entry = {
        event,
        request_id: requestId,
        timestamp: new Date().toISOString(),
        stage: diagnostics.stage,
        elapsed_ms: Number(process.hrtime.bigint() - startedAt) / 1e6,
        memory_bytes: {
          rss: memory.rss,
          heap_used: memory.heapUsed,
          heap_total: memory.heapTotal,
          external: memory.external,
          array_buffers: memory.arrayBuffers
        },
        ...details
      };

      // Registrar solo campos explícitos; nunca objetos de solicitud o de error.
      (isError ? console.error : console.log)(JSON.stringify(entry));
    },
    error(event, error, details = {}) {
      const message = String(error?.message || '');
      const timeout = /timeout|timed out|Tiempo máximo excedido/i.test(message) ||
        ['ETIMEDOUT', 'ETIMEOUT', 'CONNECT_TIMEOUT', 'GREETING_TIMEOUT',
          'SOCKET_TIMEOUT'].includes(error?.code);

      diagnostics.log(event, {
        ...details,
        timeout,
        error_code: ['ETIMEDOUT', 'ETIMEOUT', 'CONNECT_TIMEOUT',
          'GREETING_TIMEOUT', 'SOCKET_TIMEOUT', 'ECONNRESET', 'ECONNREFUSED',
          'ENOTFOUND', 'EAI_AGAIN', 'EAUTH', 'AUTHENTICATIONFAILED',
          'CERT_HAS_EXPIRED', 'DEPTH_ZERO_SELF_SIGNED_CERT']
          .includes(error?.code) ? error.code : null,
        error_type: ['Error', 'TypeError', 'RangeError', 'SyntaxError']
          .includes(error?.name) ? error.name : 'Error'
      }, true);
    },
    async run(stage, operation, details = {}) {
      diagnostics.stage = stage;
      const operationStartedAt = process.hrtime.bigint();
      diagnostics.log('stage_start', details);

      try {
        const result = await operation();
        diagnostics.log('stage_complete', {
          ...details,
          duration_ms: Number(process.hrtime.bigint() - operationStartedAt) / 1e6
        });
        return result;
      } catch (error) {
        diagnostics.failureStage ||= stage;
        diagnostics.error('stage_error', error, {
          ...details,
          duration_ms: Number(process.hrtime.bigint() - operationStartedAt) / 1e6
        });
        throw error;
      }
    }
  };

  return diagnostics;
}

async function fetchInboxBatch(config, options = {}) {
  const {
    dateFrom = null,
    dateTo = null,
    batchSize = DEFAULT_BATCH_SIZE,
    cursor = null,
    includeRead = false,
    diagnostics = createInboxDiagnostics()
  } = options;

  let client;
  let lock;

  try {
    diagnostics.stage = 'client_create';
    client = createClient(config);

    await diagnostics.run('imap_connect', () => runWithTimeout(
      () => client.connect(),
      15_000,
      () => forceCloseClient(client)
    ), { timeout_ms: 15_000 });

    lock = await diagnostics.run('mailbox_open', () => runWithTimeout(
      () => client.getMailboxLock(config.mailbox),
      15_000,
      () => forceCloseClient(client)
    ), { timeout_ms: 15_000 });

    const searchCriteria = buildSearchCriteria({ cursor });

    // No existen UID inferiores a 1; evitar el rango IMAP inválido 1:0.
    const uids = cursor === 1 ? [] : await diagnostics.run('uid_search', () => runWithTimeout(
      () =>
        client.search(
          searchCriteria,
          { uid: true }
        ),
      20_000,
      () => forceCloseClient(client)
    ), { timeout_ms: 20_000 });

    const candidateUids = Array.isArray(uids)
      ? uids.filter((uid) => !cursor || uid < cursor)
      : [];

    diagnostics.log('uid_search_result', {
      uids_found: Array.isArray(uids) ? uids.length : 0,
      candidate_uids: candidateUids.length
    });

    if (candidateUids.length === 0) {
      diagnostics.log('selection_complete', { matching_count: 0, selected_count: 0 });
      return {
        messages: [],
        failed: [],
        hasMore: false,
        nextCursor: null,
        totalMatching: 0
      };
    }

    candidateUids.sort((a, b) => b - a);

    const messages = [];
    const failed = [];

    const fromTime = dateFrom
      ? Date.parse(`${dateFrom}T00:00:00.000Z`)
      : null;
    const toTime = dateTo
      ? Date.parse(`${dateTo}T23:59:59.999Z`)
      : null;
    let totalMatching = 0;
    const selectedUids = [];
    let lastExaminedUid = null;

    // Contar coincidencias con metadatos; solo reservar contenido para una página.
    for (let offset = 0; offset < candidateUids.length; offset += batchSize) {
      const batchUids = candidateUids.slice(offset, offset + batchSize);
      const batchNumber = Math.floor(offset / batchSize) + 1;
      const batchStartedAt = process.hrtime.bigint();
      const selectedBefore = selectedUids.length;
      diagnostics.stage = 'metadata_batch';
      diagnostics.log('batch_start', {
        batch_number: batchNumber,
        batch_type: 'metadata',
        uid_count: batchUids.length
      });
      const metadata = await diagnostics.run('metadata_fetch', () => runWithTimeout(
        () =>
          client.fetchAll(
            batchUids,
            { uid: true, internalDate: true, flags: true },
            { uid: true }
          ),
        60_000,
        () => forceCloseClient(client)
      ), { batch_number: batchNumber, timeout_ms: 60_000 });
      diagnostics.stage = 'metadata_filter';
      const metadataByUid = new Map(
        (metadata || []).map((message) => [message.uid, message])
      );
      for (const uid of batchUids) {
        const pageOpen = selectedUids.length < batchSize;

        if (pageOpen) {
          lastExaminedUid = uid;
        }

        const message = metadataByUid.get(uid);

        if (!message) {
          if (pageOpen) {
            diagnostics.log('message_error', { uid, reason: 'metadata_missing' }, true);
            failed.push({ uid, error: 'Correo no devuelto por IMAP' });
          }
          continue;
        }

        if (!includeRead && message.flags.has('\\Seen')) {
          continue;
        }

        if (fromTime !== null || toTime !== null) {
          const internalTime = message.internalDate
            ? new Date(message.internalDate).getTime()
            : NaN;

          if (Number.isNaN(internalTime)) {
            if (pageOpen) {
              diagnostics.log('message_error', { uid, reason: 'invalid_internal_date' }, true);
              failed.push({ uid, error: 'Correo sin internalDate válido' });
            }
            continue;
          }

          if (
            (fromTime !== null && internalTime < fromTime) ||
            (toTime !== null && internalTime > toTime)
          ) {
            continue;
          }
        }

        totalMatching += 1;

        if (pageOpen) {
          selectedUids.push(uid);
        }
      }

      metadataByUid.clear();
      metadata.length = 0;
      diagnostics.log('batch_complete', {
        batch_number: batchNumber,
        batch_type: 'metadata',
        selected_count: selectedUids.length - selectedBefore,
        duration_ms: Number(process.hrtime.bigint() - batchStartedAt) / 1e6
      });
    }

    diagnostics.log('selection_complete', {
      matching_count: totalMatching,
      selected_count: selectedUids.length
    });

    if (selectedUids.length > 0) {
      const batchStartedAt = process.hrtime.bigint();
      diagnostics.stage = 'content_batch';
      diagnostics.log('batch_start', {
        batch_number: 1, batch_type: 'content', uid_count: selectedUids.length
      });
      const fetched = await diagnostics.run('content_fetch', () => runWithTimeout(
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
      ), { batch_number: 1, timeout_ms: 60_000 });

      const fetchedByUid = new Map();

      for (const message of fetched || []) {
        fetchedByUid.set(message.uid, message);
      }

      fetched.length = 0;

      for (const uid of selectedUids) {
        diagnostics.stage = 'content_processing';
        const rawMessage = fetchedByUid.get(uid);
        fetchedByUid.delete(uid);

        if (!rawMessage) {
          diagnostics.log('message_error', { uid, reason: 'content_missing' }, true);
          failed.push({
            uid,
            error: 'Correo no devuelto por IMAP'
          });

          continue;
        }

        try {
          const parsedMessage =
            await diagnostics.run('message_parse',
              () => parseFetchedMessage(rawMessage), { uid });

          messages.push(parsedMessage);
        } catch (error) {
          // El error ya fue registrado sin contenido por diagnostics.run().
          diagnostics.failureStage = null;

          failed.push({
            uid,
            error: error.message
          });
        } finally {
          // El contenido convertido permanece solo en la respuesta de esta página.
          rawMessage.source = null;
        }
      }

      fetchedByUid.clear();
      diagnostics.log('batch_complete', {
        batch_number: 1,
        batch_type: 'content',
        returned_count: messages.length,
        failed_count: failed.length,
        duration_ms: Number(process.hrtime.bigint() - batchStartedAt) / 1e6
      });
    }

    const hasMore = candidateUids[candidateUids.length - 1] < lastExaminedUid;

    return {
      messages,
      failed,
      hasMore,
      nextCursor: hasMore ? lastExaminedUid : null,
      totalMatching
    };
  } catch (error) {
    diagnostics.failureStage ||= diagnostics.stage;
    diagnostics.error('inbox_fetch_error', error);
    throw error;
  } finally {
    if (lock) {
      try {
        lock.release();
      } catch (error) {
        diagnostics.error('cleanup_error', error, { stage: 'lock_release' });
        // Ignorar errores de liberación.
      }
    }

    await diagnostics.run('imap_close', () => closeClient(client, diagnostics));
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
  const diagnostics = createInboxDiagnostics();
  let returnedCount = 0;
  let failedCount = 0;
  diagnostics.log('request_start');
  res.once('finish', () => diagnostics.log('request_complete', {
    stage: diagnostics.failureStage || diagnostics.stage,
    status_code: res.statusCode,
    returned_count: returnedCount,
    failed_count: failedCount
  }));
  res.once('close', () => {
    if (!res.writableFinished) {
      diagnostics.log('response_closed', {
        stage: diagnostics.failureStage || diagnostics.stage,
        returned_count: returnedCount,
        failed_count: failedCount
      }, true);
    }
  });

  try {
    diagnostics.stage = 'config_validation';
    const config = getImapConfig(req.body);

    const maskedUser = config.user.split('@')
      .map((part) => `${part.length > 1 ? part.slice(0, 1) : ''}***`)
      .join('@');
    diagnostics.log('imap_identity', { imap_user: maskedUser });
    diagnostics.stage = 'date_validation';

    const dateFrom = parseIsoDate(
      req.body.date_from,
      'date_from'
    );

    const dateTo = parseIsoDate(
      req.body.date_to,
      'date_to'
    );

    if (dateFrom && dateTo && dateFrom > dateTo) {
      diagnostics.log('validation_error', { reason: 'reversed_date_range' }, true);
      return res.status(400).json({
        success: false,
        error:
          'date_from no puede ser mayor que date_to'
      });
    }

    diagnostics.stage = 'pagination_validation';
    const batchSize = parseBatchSize(
      req.body.batch_size !== undefined
        ? req.body.batch_size
        : req.body.limit
    );

    const cursor = parseCursor(
      req.body.cursor
    );
    const includeRead = req.body.include_read === true;

    diagnostics.log('request_options', {
      date_from: dateFrom,
      date_to: dateTo,
      include_read: includeRead,
      batch_size: batchSize,
      cursor
    });

    const result = await fetchInboxBatch(
      config,
      {
        dateFrom,
        dateTo,
        batchSize,
        cursor,
        includeRead,
        diagnostics
      }
    );

    returnedCount = result.messages.length;
    failedCount = result.failed.length;
    diagnostics.stage = 'response_json';
    diagnostics.log('response_start', {
      returned_count: returnedCount,
      failed_count: failedCount,
      has_more: result.hasMore,
      next_cursor: result.nextCursor
    });

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
    diagnostics.error('request_error', error, {
      stage: diagnostics.failureStage || diagnostics.stage
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
    `Token: ${SECRET_TOKEN
      ? 'configurado'
      : 'NO configurado'
    }`
  );
});