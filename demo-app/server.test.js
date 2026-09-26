'use strict';

/**
 * Functional test suite for the demo-app REST API.
 * Covers health check, user CRUD, search, and input validation.
 */

const request = require('supertest');
const { app, db } = require('./server');

afterAll((done) => {
  db.close(done);
});

describe('GET /health', () => {
  it('responds 200 with status ok', async () => {
    const res = await request(app).get('/health');
    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual({ status: 'ok' });
  });
});

describe('GET /api/users/:id', () => {
  it('returns the seeded admin user for id 1', async () => {
    const res = await request(app).get('/api/users/1');
    expect(res.statusCode).toBe(200);
    expect(res.body.result).toMatchObject({
      id: 1,
      username: 'admin',
      email: 'admin@demo.local',
      role: 'admin'
    });
  });

  it('returns the seeded alice user for id 2', async () => {
    const res = await request(app).get('/api/users/2');
    expect(res.statusCode).toBe(200);
    expect(res.body.result).toMatchObject({
      id: 2,
      username: 'alice',
      role: 'user'
    });
  });

  it('returns 404 for a non-existent id', async () => {
    const res = await request(app).get('/api/users/999999');
    expect(res.statusCode).toBe(404);
    expect(res.body).toHaveProperty('error');
  });

  it('returns 400 for a non-numeric id (rejected by input validation)', async () => {
    const res = await request(app).get('/api/users/not-a-number');
    expect(res.statusCode).toBe(400);
    expect(res.body).toHaveProperty('error');
  });
});

describe('GET /api/users/search', () => {
  it('returns exactly one match for an exact username', async () => {
    const res = await request(app).get('/api/users/search?username=alice');
    expect(res.statusCode).toBe(200);
    expect(Array.isArray(res.body.results)).toBe(true);
    expect(res.body.results).toHaveLength(1);
    expect(res.body.results[0]).toMatchObject({ username: 'alice' });
  });

  it('returns exactly one match for another seeded username', async () => {
    const res = await request(app).get('/api/users/search?username=bob');
    expect(res.statusCode).toBe(200);
    expect(res.body.results).toHaveLength(1);
    expect(res.body.results[0]).toMatchObject({ username: 'bob' });
  });

  it('returns an empty result set for a username that does not exist', async () => {
    const res = await request(app).get('/api/users/search?username=nobody_here');
    expect(res.statusCode).toBe(200);
    expect(Array.isArray(res.body.results)).toBe(true);
    expect(res.body.results).toHaveLength(0);
  });

  it('returns an empty result set when the username param is omitted', async () => {
    const res = await request(app).get('/api/users/search');
    expect(res.statusCode).toBe(200);
    expect(Array.isArray(res.body.results)).toBe(true);
  });
});

describe('POST /api/users', () => {
  it('creates a user and returns 201 with the submitted fields', async () => {
    const res = await request(app)
      .post('/api/users')
      .send({ username: 'dave', email: 'dave@demo.local' });

    expect(res.statusCode).toBe(201);
    expect(res.body).toMatchObject({
      username: 'dave',
      email: 'dave@demo.local',
      role: 'user'
    });
    expect(typeof res.body.id).toBe('number');
  });

  it('defaults role to "user" when no role is supplied', async () => {
    const res = await request(app)
      .post('/api/users')
      .send({ username: 'erin', email: 'erin@demo.local' });

    expect(res.statusCode).toBe(201);
    expect(res.body.role).toBe('user');
  });

  it('the newly created user is immediately readable via GET /api/users/:id', async () => {
    const createRes = await request(app)
      .post('/api/users')
      .send({ username: 'frank', email: 'frank@demo.local' });

    expect(createRes.statusCode).toBe(201);
    const newId = createRes.body.id;

    const getRes = await request(app).get(`/api/users/${newId}`);
    expect(getRes.statusCode).toBe(200);
    expect(getRes.body.result).toMatchObject({
      username: 'frank',
      email: 'frank@demo.local'
    });
  });

  it('the newly created user is immediately findable via GET /api/users/search', async () => {
    await request(app)
      .post('/api/users')
      .send({ username: 'grace', email: 'grace@demo.local' });

    const searchRes = await request(app).get('/api/users/search?username=grace');
    expect(searchRes.statusCode).toBe(200);
    expect(searchRes.body.results).toHaveLength(1);
    expect(searchRes.body.results[0]).toMatchObject({ username: 'grace' });
  });
});