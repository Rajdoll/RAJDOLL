#!/usr/bin/env python3
"""
Phase 2 Database Migration Script

Adds new columns and tables for:
1. Confidence scoring (findings table)
2. Attack chain tracking (new table)
3. Knowledge graph snapshots (new table)

Run inside Docker: docker-compose exec api python migrate_phase2.py
Or directly if DB is accessible: python migrate_phase2.py
"""

import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sqlalchemy import text, inspect
from multi_agent_system.core.db import engine, Base

def run_migration():
    """Run database migration for Phase 2 architecture."""
    
    print("=" * 60)
    print("Phase 2 Database Migration")
    print("=" * 60)
    
    with engine.connect() as conn:
        inspector = inspect(engine)
        
        # 1. Add new columns to findings table
        print("\n[1/4] Checking findings table columns...")
        existing_columns = {col['name'] for col in inspector.get_columns('findings')}
        
        new_columns = {
            'confidence_score': 'ALTER TABLE findings ADD COLUMN confidence_score FLOAT',
            'confidence_level': "ALTER TABLE findings ADD COLUMN confidence_level VARCHAR(20)",
            'attack_chain_id': 'ALTER TABLE findings ADD COLUMN attack_chain_id VARCHAR(64)'
        }
        
        for col_name, sql in new_columns.items():
            if col_name not in existing_columns:
                print(f"  Adding column: {col_name}")
                try:
                    conn.execute(text(sql))
                    conn.commit()
                    print(f"  ✓ Added {col_name}")
                except Exception as e:
                    print(f"  ⚠ Column {col_name} may already exist: {e}")
            else:
                print(f"  ✓ Column {col_name} already exists")
        
        # 2. Create attack_chains table
        print("\n[2/4] Creating attack_chains table...")
        if 'attack_chains' not in inspector.get_table_names():
            conn.execute(text("""
                CREATE TABLE attack_chains (
                    id SERIAL PRIMARY KEY,
                    job_id INTEGER REFERENCES jobs(id) ON DELETE CASCADE,
                    chain_id VARCHAR(64) NOT NULL,
                    name VARCHAR(256) NOT NULL,
                    category VARCHAR(64) NOT NULL,
                    impact_multiplier FLOAT DEFAULT 1.0,
                    steps JSON NOT NULL,
                    confidence FLOAT DEFAULT 0.0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """))
            conn.commit()
            print("  ✓ Created attack_chains table")
        else:
            print("  ✓ attack_chains table already exists")
        
        # 3. Create knowledge_graph_snapshots table
        print("\n[3/4] Creating knowledge_graph_snapshots table...")
        if 'knowledge_graph_snapshots' not in inspector.get_table_names():
            conn.execute(text("""
                CREATE TABLE knowledge_graph_snapshots (
                    id SERIAL PRIMARY KEY,
                    job_id INTEGER REFERENCES jobs(id) ON DELETE CASCADE,
                    entities JSON NOT NULL,
                    relationships JSON NOT NULL,
                    agent_name VARCHAR(128),
                    snapshot_type VARCHAR(32) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """))
            conn.commit()
            print("  ✓ Created knowledge_graph_snapshots table")
        else:
            print("  ✓ knowledge_graph_snapshots table already exists")
        
        # 4. Create indexes for performance
        print("\n[4/4] Creating indexes...")
        indexes = [
            ("idx_findings_confidence", "CREATE INDEX IF NOT EXISTS idx_findings_confidence ON findings(confidence_score)"),
            ("idx_findings_chain", "CREATE INDEX IF NOT EXISTS idx_findings_chain ON findings(attack_chain_id)"),
            ("idx_attack_chains_job", "CREATE INDEX IF NOT EXISTS idx_attack_chains_job ON attack_chains(job_id)"),
            ("idx_kg_snapshots_job", "CREATE INDEX IF NOT EXISTS idx_kg_snapshots_job ON knowledge_graph_snapshots(job_id)")
        ]
        
        for idx_name, sql in indexes:
            try:
                conn.execute(text(sql))
                conn.commit()
                print(f"  ✓ Index {idx_name} ready")
            except Exception as e:
                print(f"  ⚠ Index {idx_name}: {e}")
    
    print("\n" + "=" * 60)
    print("✅ Migration completed successfully!")
    print("=" * 60)
    
    # Verify migration
    print("\nVerification:")
    with engine.connect() as conn:
        inspector = inspect(engine)
        
        # Check findings columns
        findings_cols = {col['name'] for col in inspector.get_columns('findings')}
        required_cols = {'confidence_score', 'confidence_level', 'attack_chain_id'}
        missing = required_cols - findings_cols
        if missing:
            print(f"  ⚠ Missing columns in findings: {missing}")
        else:
            print("  ✓ All new columns present in findings table")
        
        # Check new tables
        tables = set(inspector.get_table_names())
        for table in ['attack_chains', 'knowledge_graph_snapshots']:
            if table in tables:
                print(f"  ✓ Table {table} exists")
            else:
                print(f"  ⚠ Table {table} missing")


if __name__ == "__main__":
    run_migration()
