import { MigrationInterface, QueryRunner, TableIndex } from 'typeorm'
import { migrationGetTableName } from './migration-functions.js'

const INDEX_NAME = 'IDX_nonce_uuid_issuer';

export class NonceUniqueIndex1791902734377 implements MigrationInterface {
  name = 'NonceUniqueIndex1791902734377';

  async up(queryRunner: QueryRunner): Promise<void> {
    const tableName = migrationGetTableName(queryRunner, 'nonce');
    // raw SQL does not get the configured schema (DB_SCHEMA) applied, unlike the TypeORM calls below
    const schema = (queryRunner.connection.options as { schema?: string }).schema;
    const qualifiedName = schema ? `"${schema}"."${tableName}"` : `"${tableName}"`;

    // defensively remove any duplicate (uuid, issuer) rows that may already exist from
    // before the one-time-use claim()/consume() race was fixed: a unique index cannot be
    // created over duplicate data
    await queryRunner.query(
      `DELETE FROM ${qualifiedName} a USING ${qualifiedName} b WHERE a.id < b.id AND a.uuid = b.uuid AND a.issuer = b.issuer`
    );

    const table = await queryRunner.getTable(tableName);
    if (!table?.indices.find((i) => i.name === INDEX_NAME)) {
      await queryRunner.createIndex(tableName, new TableIndex({
        name: INDEX_NAME,
        columnNames: ['uuid', 'issuer'],
        isUnique: true,
      }));
    }
  }

  async down(queryRunner: QueryRunner): Promise<void> {
    const tableName = migrationGetTableName(queryRunner, 'nonce');
    const table = await queryRunner.getTable(tableName);
    if (table?.indices.find((i) => i.name === INDEX_NAME)) {
      await queryRunner.dropIndex(tableName, INDEX_NAME);
    }
  }
}
