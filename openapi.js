// OpenAPI 3.1 spec for CertaDocs public API v1.
// Served at /api/openapi.json and /.well-known/openapi.json for auto-discovery
// (Zapier + Make.com + Postman all consume this format).
//
// Keep in sync with the actual v1 routes in server.js. When adding or removing
// a route, update this file AND the route — a linter test in test-market-expansion.js
// could be added later to verify parity.

function build({ baseUrl }) {
  return {
    openapi: '3.1.0',
    info: {
      title: 'CertaDocs API',
      description: 'PDF digital-signature platform. Full REST API for creating documents, managing signers, collecting signatures, and integrating with Zapier / Make / Salesforce / custom systems.',
      version: '1.0.0',
      contact: { name: 'CertaDocs Support', email: 'support@finelai.com' },
      license: { name: 'Proprietary' },
    },
    servers: [{ url: baseUrl, description: 'This CertaDocs instance' }],
    security: [{ BearerAuth: [] }],
    components: {
      securitySchemes: {
        BearerAuth: { type: 'http', scheme: 'bearer', description: 'API key issued from Settings -> API keys.' },
      },
      schemas: {
        Document: {
          type: 'object',
          properties: {
            uuid: { type: 'string', example: 'SF-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX' },
            title: { type: 'string' },
            status: { type: 'string', enum: ['draft', 'pending', 'completed', 'cancelled', 'declined'] },
            signing_mode: { type: 'string', enum: ['sequential', 'parallel'] },
            created_at: { type: 'string', format: 'date-time' },
            completed_at: { type: 'string', format: 'date-time', nullable: true },
          },
        },
        Signer: {
          type: 'object',
          properties: {
            id: { type: 'integer' },
            name: { type: 'string' },
            email: { type: 'string', format: 'email' },
            role: { type: 'string', enum: ['sign', 'approve', 'cc', 'witness'] },
            status: { type: 'string' },
            sign_order: { type: 'integer' },
            phone: { type: 'string', nullable: true },
            preferred_language: { type: 'string', enum: ['en', 'fr', 'hi'] },
          },
        },
        Event: {
          type: 'object',
          properties: {
            id: { type: 'integer' },
            event: { type: 'string', description: 'e.g. document.sent, document.completed, signer.signed, document.declined, document.expired' },
            data: { type: 'object' },
            created_at: { type: 'string', format: 'date-time' },
          },
        },
        Webhook: {
          type: 'object',
          properties: {
            id: { type: 'integer' },
            url: { type: 'string', format: 'uri' },
            events: { type: 'array', items: { type: 'string' } },
            active: { type: 'boolean' },
            last_status: { type: 'string', nullable: true },
            last_fired_at: { type: 'string', format: 'date-time', nullable: true },
          },
        },
        Envelope: {
          type: 'object',
          properties: {
            uuid: { type: 'string' },
            title: { type: 'string' },
            status: { type: 'string' },
            signing_mode: { type: 'string' },
            created_at: { type: 'string', format: 'date-time' },
          },
        },
        Error: {
          type: 'object',
          properties: { error: { type: 'string' } },
        },
      },
      responses: {
        Unauthorized: { description: 'Missing or invalid API key', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
        NotFound:      { description: 'Resource not found',         content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
        BadRequest:    { description: 'Invalid request',             content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
      },
    },
    paths: {
      '/api/v1/documents': {
        get: {
          summary: 'List documents',
          description: 'Returns the most recent documents visible to the caller\'s API key.',
          tags: ['Documents'],
          parameters: [
            { name: 'limit', in: 'query', schema: { type: 'integer', default: 50, maximum: 200 } },
            { name: 'status', in: 'query', schema: { type: 'string' } },
          ],
          responses: {
            '200': { description: 'OK', content: { 'application/json': { schema: { type: 'object', properties: { documents: { type: 'array', items: { $ref: '#/components/schemas/Document' } } } } } } },
            '401': { $ref: '#/components/responses/Unauthorized' },
          },
        },
        post: {
          summary: 'Create document (send for signing)',
          tags: ['Documents'],
          requestBody: {
            required: true,
            content: {
              'multipart/form-data': {
                schema: {
                  type: 'object',
                  required: ['pdf', 'title', 'signers'],
                  properties: {
                    pdf: { type: 'string', format: 'binary', description: 'PDF file (max 50MB)' },
                    title: { type: 'string' },
                    message: { type: 'string' },
                    signers: { type: 'string', description: 'JSON array of signer objects' },
                    signing_mode: { type: 'string', enum: ['sequential', 'parallel'] },
                    fields: { type: 'string', description: 'JSON array of field objects' },
                  },
                },
              },
            },
          },
          responses: {
            '200': { description: 'Created', content: { 'application/json': { schema: { $ref: '#/components/schemas/Document' } } } },
            '400': { $ref: '#/components/responses/BadRequest' },
            '401': { $ref: '#/components/responses/Unauthorized' },
          },
        },
      },
      '/api/v1/documents/{uuid}': {
        get: {
          summary: 'Get one document',
          tags: ['Documents'],
          parameters: [{ name: 'uuid', in: 'path', required: true, schema: { type: 'string' } }],
          responses: {
            '200': { description: 'OK', content: { 'application/json': { schema: { $ref: '#/components/schemas/Document' } } } },
            '404': { $ref: '#/components/responses/NotFound' },
          },
        },
      },
      '/api/v1/documents/{uuid}/signers': {
        get: {
          summary: 'List signers for a document',
          tags: ['Signers'],
          parameters: [{ name: 'uuid', in: 'path', required: true, schema: { type: 'string' } }],
          responses: {
            '200': { description: 'OK', content: { 'application/json': { schema: { type: 'object', properties: { signers: { type: 'array', items: { $ref: '#/components/schemas/Signer' } } } } } } },
          },
        },
      },
      '/api/v1/events': {
        get: {
          summary: 'Poll events since a timestamp (Zapier REST-hook fallback)',
          description: 'Use this for Zapier "New X" triggers when webhooks are not available. Call every 1-5 minutes with `since` = the most recent `created_at` you received.',
          tags: ['Events', 'Zapier'],
          parameters: [
            { name: 'since', in: 'query', schema: { type: 'string', format: 'date-time' } },
            { name: 'limit', in: 'query', schema: { type: 'integer', default: 50, maximum: 200 } },
          ],
          responses: {
            '200': { description: 'OK', content: { 'application/json': { schema: { type: 'object', properties: { events: { type: 'array', items: { $ref: '#/components/schemas/Event' } } } } } } },
          },
        },
      },
      '/api/v1/webhooks': {
        get: {
          summary: 'List webhooks',
          tags: ['Webhooks'],
          responses: {
            '200': { description: 'OK', content: { 'application/json': { schema: { type: 'object', properties: { webhooks: { type: 'array', items: { $ref: '#/components/schemas/Webhook' } } } } } } },
          },
        },
        post: {
          summary: 'Create webhook (Zapier subscribe action)',
          tags: ['Webhooks', 'Zapier'],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['url'],
                  properties: {
                    url: { type: 'string', format: 'uri' },
                    events: { type: 'array', items: { type: 'string' }, default: ['*'] },
                  },
                },
              },
            },
          },
          responses: {
            '200': { description: 'Created', content: { 'application/json': { schema: { $ref: '#/components/schemas/Webhook' } } } },
          },
        },
      },
      '/api/v1/webhooks/{id}': {
        delete: {
          summary: 'Delete webhook (Zapier unsubscribe action)',
          tags: ['Webhooks', 'Zapier'],
          parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
          responses: { '200': { description: 'Deleted' } },
        },
      },
      '/api/v1/signers/{signerUuid}/embed-session': {
        post: {
          summary: 'Mint a short-lived embedded-signing token',
          tags: ['Embedded'],
          parameters: [{ name: 'signerUuid', in: 'path', required: true, schema: { type: 'string' } }],
          requestBody: {
            content: { 'application/json': { schema: { type: 'object', properties: { allowedOrigin: { type: 'string' }, ttlSeconds: { type: 'integer' } } } } },
          },
          responses: { '200': { description: 'Token' } },
        },
      },
    },
    tags: [
      { name: 'Documents', description: 'Create, list, and inspect signing documents' },
      { name: 'Signers',   description: 'Signer roster for a document' },
      { name: 'Webhooks',  description: 'Receive real-time push notifications (HMAC-signed)' },
      { name: 'Events',    description: 'Poll for events (fallback when webhooks are not possible)' },
      { name: 'Zapier',    description: 'Endpoints Zapier / Make / n8n use for REST-hook integrations' },
      { name: 'Embedded',  description: 'Embed the signing page in your own site' },
    ],
  };
}

module.exports = { build };
