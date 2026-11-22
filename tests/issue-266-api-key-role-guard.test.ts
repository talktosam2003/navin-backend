import { describe, it, expect, jest, beforeAll } from '@jest/globals';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import { signToken } from './fixtures/factories.js';
import { randomUUID } from 'crypto';
import { Types } from 'mongoose';
import type { Application } from 'express';

const JWT_SECRET = 'test-jwt-secret-key-at-least-32-chars-long!';

// Valid ObjectIds used in JWT claims and route params — per AGENTS.md §3.
const TEST_USER_ID = new Types.ObjectId().toString();
const TEST_ORG_ID = new Types.ObjectId().toString();
const TEST_KEY_ID = new Types.ObjectId().toString();

function makeToken(role: string) {
  return signToken({ userId: TEST_USER_ID, email: 'test@test.com', role, organizationId: TEST_ORG_ID, jti: randomUUID() }, { expiresIn: '1h' });
}

await jest.unstable_mockModule('../src/modules/auth/apiKey.service.js', () => ({
  generateApiKey: jest.fn<any>().mockResolvedValue({ _id: TEST_KEY_ID, apiKey: 'nvk_test123' }),
  listApiKeys: jest.fn<any>().mockResolvedValue([]),
  revokeApiKey: jest.fn<any>().mockResolvedValue(undefined),
  validateApiKey: jest.fn<any>().mockResolvedValue({ isValid: false }),
}));

await jest.unstable_mockModule('../src/modules/auth/auth.service.js', () => ({
  signup: jest.fn(),
  login: jest.fn(),
  logout: jest.fn(),
  verifyToken: jest.fn((token: string) => jwt.verify(token, JWT_SECRET) as { userId: string; role: string; jti?: string }),
  forgotPassword: jest.fn(),
  resetPassword: jest.fn(),
  refreshToken: jest.fn(),
  registerCompany: jest.fn(),
  setup2fa: jest.fn(),
  changePassword: jest.fn(),
}));

await jest.unstable_mockModule('../src/infra/redis/connection.js', () => ({
  getRedisClient: () => ({
    get: jest.fn(async () => null),
    set: jest.fn(async () => 'OK'),
    exists: jest.fn(async () => 0),
  }),
  getRedisConnection: () => ({
    get: jest.fn(async () => null),
    set: jest.fn(async () => 'OK'),
  }),
  disconnectRedis: jest.fn(async () => undefined),
}));

await jest.unstable_mockModule('../src/infra/redis/tokenBlocklist.js', () => ({
  isTokenBlocked: jest.fn(async () => false),
  blockToken: jest.fn(async () => undefined),
  BLOCKLIST_PREFIX: 'blocklist:uuid:',
  isValidJti: jest.fn(() => true),
}));

const { authRouter } = await import('../src/modules/auth/auth.routes.js');
const express = await import('express');
const { errorMiddleware } = await import('../src/shared/http/errorMiddleware.js');

function createApp(): Application {
  const app = express.default();
  app.use(express.json());
  app.use('/api/auth', authRouter);
  app.use(errorMiddleware());
  return app;
}

describe('Issue #266: requireRole on API key management routes', () => {
  let app: Application;

  beforeAll(() => {
    app = createApp();
  });

  describe('POST /api/auth/api-keys', () => {
    it('returns 403 for VIEWER role', async () => {
      const res = await request(app)
        .post('/api/auth/api-keys')
        .set('Authorization', `Bearer ${makeToken('VIEWER')}`)
        .send({ name: 'test-key', organizationId: TEST_ORG_ID });
      expect(res.status).toBe(403);
    });

    it('returns 403 for CUSTOMER role', async () => {
      const res = await request(app)
        .post('/api/auth/api-keys')
        .set('Authorization', `Bearer ${makeToken('CUSTOMER')}`)
        .send({ name: 'test-key', organizationId: TEST_ORG_ID });
      expect(res.status).toBe(403);
    });

    it('allows ADMIN role', async () => {
      const res = await request(app)
        .post('/api/auth/api-keys')
        .set('Authorization', `Bearer ${makeToken('ADMIN')}`)
        .send({ name: 'test-key', organizationId: TEST_ORG_ID });
      expect(res.status).toBe(201);
    });

    it('allows SUPER_ADMIN role', async () => {
      const res = await request(app)
        .post('/api/auth/api-keys')
        .set('Authorization', `Bearer ${makeToken('SUPER_ADMIN')}`)
        .send({ name: 'test-key', organizationId: TEST_ORG_ID });
      expect(res.status).toBe(201);
    });

    it('returns 401 without token', async () => {
      const res = await request(app)
        .post('/api/auth/api-keys')
        .send({ name: 'test-key', organizationId: TEST_ORG_ID });
      expect(res.status).toBe(401);
    });
  });

  describe('GET /api/auth/api-keys/:organizationId', () => {
    it('returns 403 for VIEWER role', async () => {
      const res = await request(app)
        .get(`/api/auth/api-keys/${TEST_ORG_ID}`)
        .set('Authorization', `Bearer ${makeToken('VIEWER')}`);
      expect(res.status).toBe(403);
    });

    it('returns 403 for MANAGER role', async () => {
      const res = await request(app)
        .get(`/api/auth/api-keys/${TEST_ORG_ID}`)
        .set('Authorization', `Bearer ${makeToken('MANAGER')}`);
      expect(res.status).toBe(403);
    });

    it('allows ADMIN role', async () => {
      const res = await request(app)
        .get(`/api/auth/api-keys/${TEST_ORG_ID}`)
        .set('Authorization', `Bearer ${makeToken('ADMIN')}`);
      expect(res.status).toBe(200);
    });

    it('allows SUPER_ADMIN role', async () => {
      const res = await request(app)
        .get(`/api/auth/api-keys/${TEST_ORG_ID}`)
        .set('Authorization', `Bearer ${makeToken('SUPER_ADMIN')}`);
      expect(res.status).toBe(200);
    });

    it('returns 401 without token', async () => {
      const res = await request(app)
        .get(`/api/auth/api-keys/${TEST_ORG_ID}`);
      expect(res.status).toBe(401);
    });
  });

  describe('DELETE /api/auth/api-keys/:apiKeyId', () => {
    it('returns 403 for VIEWER role', async () => {
      const res = await request(app)
        .delete(`/api/auth/api-keys/${TEST_KEY_ID}`)
        .set('Authorization', `Bearer ${makeToken('VIEWER')}`);
      expect(res.status).toBe(403);
    });

    it('returns 403 for CUSTOMER role', async () => {
      const res = await request(app)
        .delete(`/api/auth/api-keys/${TEST_KEY_ID}`)
        .set('Authorization', `Bearer ${makeToken('CUSTOMER')}`);
      expect(res.status).toBe(403);
    });

    it('allows ADMIN role', async () => {
      const res = await request(app)
        .delete(`/api/auth/api-keys/${TEST_KEY_ID}`)
        .set('Authorization', `Bearer ${makeToken('ADMIN')}`);
      expect(res.status).toBe(200);
    });

    it('allows SUPER_ADMIN role', async () => {
      const res = await request(app)
        .delete(`/api/auth/api-keys/${TEST_KEY_ID}`)
        .set('Authorization', `Bearer ${makeToken('SUPER_ADMIN')}`);
      expect(res.status).toBe(200);
    });

    it('returns 401 without token', async () => {
      const res = await request(app)
        .delete(`/api/auth/api-keys/${TEST_KEY_ID}`);
      expect(res.status).toBe(401);
    });
  });
});
