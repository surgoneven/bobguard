'use strict';

const request = require('supertest');
const { app, db } = require('../server');

afterAll((done) => {
  db.close(done);
});

describe('GET /health', () => {
  it('returns ok status', async () => {
    const res = await request(app).get('/health');
    expect(res.statusCode).toBe(200);
    expect(res.body.status).toBe('ok');
  });
});

describe('GET /api/users/:id', () => {
  it('returns user for valid id', async () => {
    const res = await request(app).get('/api/users/1');
    expect(res.statusCode).toBe(200);
    expect(res.body.result).toHaveProperty('username', 'admin');
  });

  it('returns 404 for missing id', async () => {
    const res = await request(app).get('/api/users/9999');
    expect(res.statusCode).toBe(404);
  });
});

describe('GET /api/users/search', () => {
  it('returns matching user for exact username', async () => {
    const res = await request(app).get('/api/users/search?username=alice');
    expect(res.statusCode).toBe(200);
    expect(Array.isArray(res.body.results)).toBe(true);
    expect(res.body.results.length).toBe(1);
    expect(res.body.results[0].username).toBe('alice');
  });

});

describe('POST /api/users', () => {
  it('creates a user with default role', async () => {
    const res = await request(app)
      .post('/api/users')
      .send({ username: 'carol', email: 'carol@demo.local' });
    expect(res.statusCode).toBe(201);
    expect(res.body.role).toBe('user');
  });

});
