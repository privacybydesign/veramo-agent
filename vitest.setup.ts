import { vi } from 'vitest';

// Stub the database layer so importing modules that reach for a DB connection
// (e.g. Issuer -> getDbConnection) does not open a real connection during tests.
vi.mock('./src/database/databaseService');

// NOTE: Issuer is intentionally NOT mocked. Several suites (credential formats,
// validateAccessTokenRequest, ...) construct a real Issuer and assert on its
// real output; a global automock turns the class into a non-constructable spy
// and breaks them.
